import { NextRequest, NextResponse } from 'next/server';
import { requireAdministrator, AuthError } from '@/lib/auth';
import { createClient } from '@/lib/supabase-server';
import { logAuditEvent } from '@/lib/audit';
import type { Profile } from '@/lib/types';

export async function GET() {
  try {
    await requireAdministrator();
    const client = createClient();
    const { data, error } = await client.rpc('list_all_users');

    if (error) {
      return NextResponse.json({ error: 'Failed to fetch users' }, { status: 500 });
    }

    return NextResponse.json({ users: (data as Profile[]) || [] });
  } catch (err) {
    if (err instanceof AuthError) {
      return NextResponse.json({ error: err.message }, { status: err.code === 'UNAUTHENTICATED' ? 401 : 403 });
    }
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    const admin = await requireAdministrator();
    const body = await req.json();
    const { user_id, role, status } = body;

    if (!user_id) {
      return NextResponse.json({ error: 'user_id required' }, { status: 400 });
    }

    if (user_id === admin.id) {
      return NextResponse.json({ error: 'Cannot modify your own role' }, { status: 400 });
    }

    const updates: Record<string, string> = {};
    if (role && ['admin', 'owner', 'viewer'].includes(role)) updates.role = role;
    if (status && ['active', 'suspended'].includes(status)) updates.status = status;

    if (Object.keys(updates).length === 0) {
      return NextResponse.json({ error: 'No valid updates' }, { status: 400 });
    }

    const client = createClient();
    const { data, error } = await client.rpc('update_user_role_status', {
      p_target_user_id: user_id,
      p_role: role || null,
      p_status: status || null,
    });

    if (error || !data || (data as Profile[]).length === 0) {
      return NextResponse.json({ error: 'Failed to update user' }, { status: 400 });
    }

    await logAuditEvent({
      actor_id: admin.id,
      action: 'admin_user_updated',
      target_user_id: user_id,
      outcome: 'success',
      metadata: { changes: updates },
    });

    return NextResponse.json({ user: (data as Profile[])[0] });
  } catch (err) {
    if (err instanceof AuthError) {
      return NextResponse.json({ error: err.message }, { status: err.code === 'UNAUTHENTICATED' ? 401 : 403 });
    }
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
