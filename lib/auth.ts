import { createClient } from '@/lib/supabase-server';
import type { AuthUser, UserRole, DocumentOperation, Document, Profile } from '@/lib/types';
import { logAuditEvent } from '@/lib/audit';
import { headers } from 'next/headers';

export class AuthError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function getRequestCorrelationId(): string {
  try {
    const h = headers();
    return h.get('x-request-id') || h.get('x-correlation-id') || '';
  } catch {
    return '';
  }
}

export async function getSessionUser(): Promise<AuthUser | null> {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session?.user) return null;

  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', session.user.id)
    .maybeSingle();

  if (!profile) return null;

  return {
    id: session.user.id,
    email: session.user.email || profile.email,
    profile: profile as Profile,
  };
}

export async function requireAuthenticatedUser(): Promise<AuthUser> {
  const user = await getSessionUser();
  if (!user) {
    throw new AuthError('UNAUTHENTICATED', 'Authentication required');
  }
  if (user.profile.status === 'suspended') {
    throw new AuthError('SUSPENDED', 'Account suspended');
  }
  return user;
}

export async function requireAdministrator(): Promise<AuthUser> {
  const user = await requireAuthenticatedUser();
  if (user.profile.role !== 'admin') {
    await logAuditEvent({
      actor_id: user.id,
      action: 'admin_access_denied',
      outcome: 'denied',
      request_id: getRequestCorrelationId(),
      metadata: { attempted_role: 'admin' },
    });
    throw new AuthError('FORBIDDEN', 'Administrator access required');
  }
  return user;
}

export async function canReadDocument(userId: string, document: Document): Promise<boolean> {
  if (document.owner_id === userId) return true;
  if (document.status === 'deleted') return false;

  const client = createClient();
  const { data } = await client
    .from('document_permissions')
    .select('granted')
    .eq('document_id', document.id)
    .eq('user_id', userId)
    .eq('granted', true)
    .maybeSingle();

  return !!data;
}

export async function canEditDocument(userId: string, document: Document): Promise<boolean> {
  if (document.owner_id === userId) return true;
  if (document.status === 'deleted') return false;

  const client = createClient();
  const { data } = await client
    .from('document_permissions')
    .select('access_level, granted')
    .eq('document_id', document.id)
    .eq('user_id', userId)
    .eq('granted', true)
    .maybeSingle();

  return data?.access_level === 'edit';
}

export async function canManageDocumentAccess(userId: string, document: Document): Promise<boolean> {
  return document.owner_id === userId;
}

export async function authoriseDocumentOperation(
  user: AuthUser,
  document: Document,
  operation: DocumentOperation,
): Promise<void> {
  const correlationId = getRequestCorrelationId();

  let allowed = false;
  switch (operation) {
    case 'read':
    case 'preview':
    case 'download':
      allowed = await canReadDocument(user.id, document);
      break;
    case 'edit':
      allowed = await canEditDocument(user.id, document);
      break;
    case 'delete':
    case 'manage_access':
      allowed = await canManageDocumentAccess(user.id, document);
      break;
    case 'upload':
      allowed = true;
      break;
  }

  if (!allowed) {
    await logAuditEvent({
      actor_id: user.id,
      action: `document_${operation}_denied`,
      document_id: document.id,
      outcome: 'denied',
      request_id: correlationId,
      metadata: { operation, document_title: document.title },
    });
    throw new AuthError('FORBIDDEN', `Not authorised to ${operation} this document`);
  }

  await logAuditEvent({
    actor_id: user.id,
    action: `document_${operation}`,
    document_id: document.id,
    outcome: 'success',
    request_id: correlationId,
    metadata: { operation },
  });
}

export async function getDocumentForAuthorisedCheck(
  documentId: string,
): Promise<Document | null> {
  const client = createClient();
  const { data } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();
  return data as Document | null;
}
