import { createClient } from '@/lib/supabase-server';
import { logAuditEvent } from '@/lib/audit';
import { requireAuthenticatedUser, canReadDocument, canEditDocument, canManageDocumentAccess, AuthError } from '@/lib/auth';
import {
  uploadSchema, updateDocumentSchema, grantPermissionSchema,
  isAllowedFileType, verifyFileSignature, isExecutableFile,
  getFileExtension, sanitizeFilename, generateStorageKey,
  MAX_FILE_SIZE,
} from '@/lib/validation';
import type { Document, DocumentPermission, Profile, DocumentVersion } from '@/lib/types';
import { headers } from 'next/headers';

const STORAGE_BUCKET = 'documents';

function getCorrelationId(): string {
  try {
    const h = headers();
    return h.get('x-request-id') || '';
  } catch {
    return '';
  }
}

export async function uploadDocument(
  file: File,
  metadata: { title: string; description?: string; category?: string },
): Promise<{ document: Document | null; error: string | null }> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();

  const parsed = uploadSchema.safeParse(metadata);
  if (!parsed.success) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_upload_validation_failed',
      outcome: 'error',
      request_id: correlationId,
      metadata: { errors: parsed.error.issues },
    });
    return { document: null, error: parsed.error.issues[0]?.message || 'Invalid metadata' };
  }

  if (file.size > MAX_FILE_SIZE) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_upload_size_exceeded',
      outcome: 'denied',
      request_id: correlationId,
      metadata: { file_size: file.size, max_size: MAX_FILE_SIZE },
    });
    return { document: null, error: `File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB` };
  }

  const ext = getFileExtension(file.name);
  if (!isAllowedFileType(file.name, file.type)) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_upload_type_rejected',
      outcome: 'denied',
      request_id: correlationId,
      metadata: { filename: sanitizeFilename(file.name), file_type: file.type },
    });
    return { document: null, error: 'File type not allowed' };
  }

  if (isExecutableFile(file.name)) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_upload_executable_rejected',
      outcome: 'denied',
      request_id: correlationId,
      metadata: { filename: sanitizeFilename(file.name) },
    });
    return { document: null, error: 'Executable files are not allowed' };
  }

  const buffer = await file.arrayBuffer();
  if (!verifyFileSignature(buffer, ext)) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_upload_signature_mismatch',
      outcome: 'denied',
      request_id: correlationId,
      metadata: { filename: sanitizeFilename(file.name), declared_type: file.type },
    });
    return { document: null, error: 'File signature does not match declared type' };
  }

  const storageKey = generateStorageKey(user.id, ext);
  const safeFilename = sanitizeFilename(file.name);

  const client = createClient();
  const { error: uploadError } = await client.storage
    .from(STORAGE_BUCKET)
    .upload(storageKey, buffer, {
      contentType: file.type,
      upsert: false,
    });

  if (uploadError) {
    return { document: null, error: 'Failed to upload file to storage' };
  }

  const { data: docData, error: docError } = await client
    .from('documents')
    .insert({
      owner_id: user.id,
      title: parsed.data.title,
      description: parsed.data.description || '',
      category: parsed.data.category,
      file_name: safeFilename,
      file_type: ext,
      file_size: file.size,
      storage_key: storageKey,
      status: 'active',
      version_number: 1,
    })
    .select('*')
    .maybeSingle();

  if (docError || !docData) {
    await client.storage.from(STORAGE_BUCKET).remove([storageKey]);
    return { document: null, error: 'Failed to create document record' };
  }

  const document = docData as Document;

  await client.from('document_versions').insert({
    document_id: document.id,
    version_number: 1,
    file_name: safeFilename,
    file_type: ext,
    file_size: file.size,
    storage_key: storageKey,
    uploaded_by: user.id,
    change_summary: 'Initial upload',
  });

  await logAuditEvent({
    actor_id: user.id,
    action: 'document_upload',
    document_id: document.id,
    outcome: 'success',
    request_id: correlationId,
    metadata: { title: parsed.data.title, file_type: ext, file_size: file.size },
  });

  return { document, error: null };
}

export async function listDocuments(params: {
  search?: string;
  category?: string;
  accessLevel?: string;
  page?: number;
  pageSize?: number;
}): Promise<{ documents: (Document & { owner_email?: string; owner_name?: string; access_level?: string })[]; total: number }> {
  const user = await requireAuthenticatedUser();
  const client = createClient();
  const page = params.page || 1;
  const pageSize = params.pageSize || 20;
  const offset = (page - 1) * pageSize;

  let query = client
    .from('documents')
    .select('*, document_permissions(access_level, granted, user_id)', { count: 'exact' });

  if (params.search) {
    query = query.or(`title.ilike.%${params.search}%,description.ilike.%${params.search}%`);
  }
  if (params.category && params.category !== 'all') {
    query = query.eq('category', params.category);
  }

  query = query.neq('status', 'deleted')
    .order('created_at', { ascending: false })
    .range(offset, offset + pageSize - 1);

  const { data, count } = await query;

  const visibleDocs: (Document & { owner_email?: string; owner_name?: string; access_level?: string })[] = [];
  if (data) {
    for (const doc of data) {
      const d = doc as Document & { document_permissions?: DocumentPermission[] };
      const isOwner = d.owner_id === user.id;
      const perm = d.document_permissions?.find(
        (p) => p.user_id === user.id && p.granted === true,
      );
      if (isOwner || perm || user.profile.role === 'admin') {
        const { data: ownerProfile } = await client
          .from('profiles')
          .select('email, display_name')
          .eq('id', d.owner_id)
          .maybeSingle();
        visibleDocs.push({
          ...d,
          owner_email: ownerProfile?.email,
          owner_name: ownerProfile?.display_name,
          access_level: isOwner ? 'owner' : perm?.access_level,
        });
      }
    }
  }

  return { documents: visibleDocs, total: count || 0 };
}

export async function getDocumentDetail(documentId: string): Promise<{
  document: Document | null;
  owner: Profile | null;
  permissions: DocumentPermission[];
  versions: DocumentVersion[];
  error: string | null;
}> {
  const user = await requireAuthenticatedUser();
  const client = createClient();

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { document: null, owner: null, permissions: [], versions: [], error: 'Document not found' };
  }

  const document = doc as Document;

  const hasAccess = await canReadDocument(user.id, document);
  if (!hasAccess) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_detail_denied',
      document_id: documentId,
      outcome: 'denied',
      request_id: getCorrelationId(),
      metadata: {},
    });
    return { document: null, owner: null, permissions: [], versions: [], error: 'Access denied' };
  }

  const [ownerResult, permResult, versionResult] = await Promise.all([
    client.from('profiles').select('*').eq('id', document.owner_id).maybeSingle(),
    client.from('document_permissions').select('*').eq('document_id', documentId).eq('granted', true),
    client.from('document_versions').select('*').eq('document_id', documentId).order('version_number', { ascending: false }),
  ]);

  const canManage = await canManageDocumentAccess(user.id, document);
  const permissions = canManage ? (permResult.data as DocumentPermission[]) : [];

  await logAuditEvent({
    actor_id: user.id,
    action: 'document_detail_viewed',
    document_id: documentId,
    outcome: 'success',
    request_id: getCorrelationId(),
    metadata: {},
  });

  return {
    document,
    owner: ownerResult.data as Profile | null,
    permissions,
    versions: (versionResult.data as DocumentVersion[]) || [],
    error: null,
  };
}

export async function downloadDocument(documentId: string): Promise<{
  data: ArrayBuffer | null;
  contentType: string;
  fileName: string;
  error: string | null;
}> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();
  const client = createClient();

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_download_denied',
      document_id: documentId,
      outcome: 'denied',
      request_id: correlationId,
      metadata: { reason: 'not_found' },
    });
    return { data: null, contentType: '', fileName: '', error: 'Document not found' };
  }

  const document = doc as Document;

  const hasAccess = await canReadDocument(user.id, document);
  if (!hasAccess) {
    return { data: null, contentType: '', fileName: '', error: 'Access denied' };
  }

  const { data: fileData, error: downloadError } = await client.storage
    .from(STORAGE_BUCKET)
    .download(document.storage_key);

  if (downloadError || !fileData) {
    return { data: null, contentType: '', fileName: '', error: 'Failed to download file' };
  }

  const contentType = fileData.type || 'application/octet-stream';
  const arrayBuffer = await fileData.arrayBuffer();

  await logAuditEvent({
    actor_id: user.id,
    action: 'document_download',
    document_id: documentId,
    outcome: 'success',
    request_id: correlationId,
    metadata: { file_name: document.file_name, file_size: document.file_size },
  });

  return { data: arrayBuffer, contentType, fileName: document.file_name, error: null };
}

export async function updateDocumentMetadata(
  documentId: string,
  updates: { title?: string; description?: string; category?: string },
): Promise<{ document: Document | null; error: string | null }> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();
  const client = createClient();

  const parsed = updateDocumentSchema.safeParse(updates);
  if (!parsed.success) {
    return { document: null, error: parsed.error.issues[0]?.message || 'Invalid input' };
  }

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { document: null, error: 'Document not found' };
  }

  const document = doc as Document;
  const canEdit = await canEditDocument(user.id, document);
  if (!canEdit) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_update_denied',
      document_id: documentId,
      outcome: 'denied',
      request_id: correlationId,
      metadata: {},
    });
    return { document: null, error: 'Access denied' };
  }

  const { data: updated, error } = await client
    .from('documents')
    .update(parsed.data)
    .eq('id', documentId)
    .select('*')
    .maybeSingle();

  if (error || !updated) {
    return { document: null, error: 'Failed to update document' };
  }

  await logAuditEvent({
    actor_id: user.id,
    action: 'document_metadata_updated',
    document_id: documentId,
    outcome: 'success',
    request_id: correlationId,
    metadata: { changes: parsed.data },
  });

  return { document: updated as Document, error: null };
}

export async function deleteDocument(documentId: string): Promise<{ error: string | null }> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();
  const client = createClient();

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { error: 'Document not found' };
  }

  const document = doc as Document;

  if (document.owner_id !== user.id) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'document_delete_denied',
      document_id: documentId,
      outcome: 'denied',
      request_id: correlationId,
      metadata: {},
    });
    return { error: 'Only the owner can delete this document' };
  }

  await client.storage.from(STORAGE_BUCKET).remove([document.storage_key]);

  const { error: deleteError } = await client
    .from('documents')
    .delete()
    .eq('id', documentId);

  if (deleteError) {
    return { error: 'Failed to delete document' };
  }

  await logAuditEvent({
    actor_id: user.id,
    action: 'document_deleted',
    document_id: documentId,
    outcome: 'success',
    request_id: correlationId,
    metadata: { title: document.title },
  });

  return { error: null };
}

export async function grantPermission(
  documentId: string,
  targetUserId: string,
  accessLevel: 'read' | 'edit',
): Promise<{ error: string | null }> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();
  const client = createClient();

  const parsed = grantPermissionSchema.safeParse({ user_id: targetUserId, access_level: accessLevel });
  if (!parsed.success) {
    return { error: 'Invalid permission data' };
  }

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { error: 'Document not found' };
  }

  const document = doc as Document;

  if (document.owner_id !== user.id) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'permission_grant_denied',
      document_id: documentId,
      target_user_id: targetUserId,
      outcome: 'denied',
      request_id: correlationId,
      metadata: {},
    });
    return { error: 'Only the owner can manage permissions' };
  }

  if (targetUserId === user.id) {
    return { error: 'Cannot grant permission to yourself' };
  }

  const { data: targetProfile } = await client
    .from('profiles')
    .select('status')
    .eq('id', targetUserId)
    .maybeSingle();

  if (!targetProfile || targetProfile.status !== 'active') {
    return { error: 'Target user not found or inactive' };
  }

  const { data: existing } = await client
    .from('document_permissions')
    .select('id')
    .eq('document_id', documentId)
    .eq('user_id', targetUserId)
    .maybeSingle();

  if (existing) {
    const { error } = await client
      .from('document_permissions')
      .update({ access_level: accessLevel, granted: true, granted_by: user.id })
      .eq('id', existing.id);

    if (error) return { error: 'Failed to update permission' };
  } else {
    const { error } = await client
      .from('document_permissions')
      .insert({
        document_id: documentId,
        user_id: targetUserId,
        access_level: accessLevel,
        granted: true,
        granted_by: user.id,
      });

    if (error) return { error: 'Failed to grant permission' };
  }

  await logAuditEvent({
    actor_id: user.id,
    action: 'permission_granted',
    document_id: documentId,
    target_user_id: targetUserId,
    outcome: 'success',
    request_id: correlationId,
    metadata: { access_level: accessLevel },
  });

  return { error: null };
}

export async function revokePermission(
  documentId: string,
  targetUserId: string,
): Promise<{ error: string | null }> {
  const user = await requireAuthenticatedUser();
  const correlationId = getCorrelationId();
  const client = createClient();

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { error: 'Document not found' };
  }

  const document = doc as Document;

  if (document.owner_id !== user.id) {
    await logAuditEvent({
      actor_id: user.id,
      action: 'permission_revoke_denied',
      document_id: documentId,
      target_user_id: targetUserId,
      outcome: 'denied',
      request_id: correlationId,
      metadata: {},
    });
    return { error: 'Only the owner can manage permissions' };
  }

  const { error } = await client
    .from('document_permissions')
    .update({ granted: false })
    .eq('document_id', documentId)
    .eq('user_id', targetUserId);

  if (error) return { error: 'Failed to revoke permission' };

  await logAuditEvent({
    actor_id: user.id,
    action: 'permission_revoked',
    document_id: documentId,
    target_user_id: targetUserId,
    outcome: 'success',
    request_id: correlationId,
    metadata: {},
  });

  return { error: null };
}

export async function searchUsers(query: string): Promise<Profile[]> {
  const user = await requireAuthenticatedUser();
  const client = createClient();

  const { data } = await client
    .from('profiles')
    .select('*')
    .eq('status', 'active')
    .neq('id', user.id)
    .or(`email.ilike.%${query}%,display_name.ilike.%${query}%`)
    .limit(20);

  return (data as Profile[]) || [];
}

export async function getDocumentPermissions(documentId: string): Promise<{
  permissions: (DocumentPermission & { user_email?: string; user_name?: string })[];
  error: string | null;
}> {
  const user = await requireAuthenticatedUser();
  const client = createClient();

  const { data: doc } = await client
    .from('documents')
    .select('*')
    .eq('id', documentId)
    .maybeSingle();

  if (!doc) {
    return { permissions: [], error: 'Document not found' };
  }

  const document = doc as Document;

  if (document.owner_id !== user.id) {
    return { permissions: [], error: 'Only the owner can view all permissions' };
  }

  const { data: perms } = await client
    .from('document_permissions')
    .select('*')
    .eq('document_id', documentId)
    .eq('granted', true);

  const result: (DocumentPermission & { user_email?: string; user_name?: string })[] = [];
  if (perms) {
    for (const perm of perms as DocumentPermission[]) {
      const { data: profile } = await client
        .from('profiles')
        .select('email, display_name')
        .eq('id', perm.user_id)
        .maybeSingle();
      result.push({
        ...perm,
        user_email: profile?.email,
        user_name: profile?.display_name,
      });
    }
  }

  return { permissions: result, error: null };
}
