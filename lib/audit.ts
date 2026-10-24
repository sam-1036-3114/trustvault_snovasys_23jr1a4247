import { createClient } from '@/lib/supabase-server';
import type { AuditOutcome } from '@/lib/types';

interface AuditParams {
  actor_id?: string | null;
  action: string;
  document_id?: string | null;
  target_user_id?: string | null;
  outcome?: AuditOutcome;
  request_id?: string;
  metadata?: Record<string, unknown>;
}

export async function logAuditEvent(params: AuditParams): Promise<string | null> {
  try {
    const client = createClient();
    const { data, error } = await client.rpc('insert_audit_event', {
      p_actor_id: params.actor_id ?? null,
      p_action: params.action,
      p_document_id: params.document_id ?? null,
      p_target_user_id: params.target_user_id ?? null,
      p_outcome: params.outcome ?? 'success',
      p_request_id: params.request_id ?? '',
      p_metadata: params.metadata ?? {},
      p_chain_id: 'main',
    });

    if (error) {
      console.error('Audit log error:', error.message);
      return null;
    }
    return data as string;
  } catch (err) {
    console.error('Audit log exception:', err);
    return null;
  }
}

export async function verifyAuditIntegrity() {
  const client = createClient();
  const { data, error } = await client.rpc('verify_audit_chain', {
    p_chain_id: 'main',
  });
  if (error) throw error;
  return data;
}
