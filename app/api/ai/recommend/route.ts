import { NextRequest, NextResponse } from 'next/server';
import { requireAuthenticatedUser, AuthError, canManageDocumentAccess } from '@/lib/auth';
import { createClient } from '@/lib/supabase-server';
import { getDocumentForAuthorisedCheck } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { headers } from 'next/headers';

export async function POST(req: NextRequest) {
  try {
    const user = await requireAuthenticatedUser();
    const body = await req.json();
    const { document_id, context } = body;

    if (!document_id) {
      return NextResponse.json({ error: 'document_id required' }, { status: 400 });
    }

    const document = await getDocumentForAuthorisedCheck(document_id);
    if (!document) {
      return NextResponse.json({ error: 'Document not found' }, { status: 404 });
    }

    const canManage = await canManageDocumentAccess(user.id, document);
    if (!canManage) {
      await logAuditEvent({
        actor_id: user.id,
        action: 'ai_recommendation_denied',
        document_id,
        outcome: 'denied',
        request_id: headers().get('x-request-id') || '',
        metadata: {},
      });
      return NextResponse.json({ error: 'Only the owner can request recommendations' }, { status: 403 });
    }

    const client = createClient();

    const { data: permissions } = await client
      .from('document_permissions')
      .select('user_id, access_level, granted')
      .eq('document_id', document_id)
      .eq('granted', true);

    const activeGrants = permissions || [];
    const recommendations: Array<{ type: string; message: string; severity: string }> = [];

    if (activeGrants.length > 5) {
      recommendations.push({
        type: 'broad_access',
        message: `This document is shared with ${activeGrants.length} users. Consider reviewing whether all grants are still necessary.`,
        severity: 'medium',
      });
    }

    const editGrants = activeGrants.filter((p: { access_level: string }) => p.access_level === 'edit');
    if (editGrants.length > 3) {
      recommendations.push({
        type: 'excessive_edit',
        message: `${editGrants.length} users have edit access. Consider whether read access would be sufficient for some users.`,
        severity: 'low',
      });
    }

    if (context && context.toLowerCase().includes('confidential')) {
      recommendations.push({
        type: 'confidential_warning',
        message: 'You mentioned this document is confidential. Consider limiting access to only essential personnel and using read-only grants where possible.',
        severity: 'high',
      });
    }

    recommendations.push({
      type: 'permission_explanation',
      message: 'Read access allows users to view and download the document. Edit access also allows them to modify document metadata. Neither level allows sharing or deleting the document.',
      severity: 'info',
    });

    await logAuditEvent({
      actor_id: user.id,
      action: 'ai_recommendation_requested',
      document_id,
      outcome: 'success',
      request_id: headers().get('x-request-id') || '',
      metadata: { recommendation_count: recommendations.length },
    });

    return NextResponse.json({
      recommendations,
      disclaimer: 'These recommendations are advisory only. AI cannot grant, modify, or revoke permissions. You must explicitly confirm any permission changes.',
    });
  } catch (err) {
    if (err instanceof AuthError) {
      return NextResponse.json({ error: err.message }, { status: err.code === 'UNAUTHENTICATED' ? 401 : 403 });
    }
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
