export type UserRole = 'admin' | 'owner' | 'viewer';
export type AccountStatus = 'active' | 'suspended';
export type AccessLevel = 'read' | 'edit';
export type DocumentStatus = 'active' | 'archived' | 'deleted';
export type AuditOutcome = 'success' | 'denied' | 'error';

export interface Profile {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  status: AccountStatus;
  created_at: string;
  updated_at: string;
}

export interface Document {
  id: string;
  owner_id: string;
  title: string;
  description: string;
  category: string;
  file_name: string;
  file_type: string;
  file_size: number;
  storage_key: string;
  status: DocumentStatus;
  version_number: number;
  created_at: string;
  updated_at: string;
}

export interface DocumentVersion {
  id: string;
  document_id: string;
  version_number: number;
  file_name: string;
  file_type: string;
  file_size: number;
  storage_key: string;
  uploaded_by: string;
  change_summary: string;
  created_at: string;
}

export interface DocumentPermission {
  id: string;
  document_id: string;
  user_id: string;
  access_level: AccessLevel;
  granted: boolean;
  granted_by: string;
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: string;
  sequence_number: number;
  event_timestamp: string;
  actor_id: string | null;
  action: string;
  document_id: string | null;
  target_user_id: string | null;
  outcome: AuditOutcome;
  request_id: string;
  metadata: Record<string, unknown>;
  previous_hash: string;
  current_hash: string;
  chain_id: string;
}

export interface SecurityAlert {
  id: string;
  alert_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  actor_id: string | null;
  document_id: string | null;
  description: string;
  metadata: Record<string, unknown>;
  acknowledged: boolean;
  acknowledged_by: string | null;
  created_at: string;
}

export interface OrganisationSettings {
  id: number;
  org_name: string;
  max_file_size_bytes: number;
  allowed_file_types: string[];
  created_at: string;
  updated_at: string;
}

export interface AuthUser {
  id: string;
  email: string;
  profile: Profile;
}

export interface AuditChainVerification {
  is_valid: boolean;
  total_events: number;
  verified_events: number;
  first_invalid_sequence: number;
  error_message: string;
}

export type DocumentOperation = 'read' | 'preview' | 'download' | 'edit' | 'delete' | 'manage_access' | 'upload';

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: Profile;
        Insert: Partial<Profile>;
        Update: Partial<Profile>;
      };
      documents: {
        Row: Document;
        Insert: Partial<Document>;
        Update: Partial<Document>;
      };
      document_versions: {
        Row: DocumentVersion;
        Insert: Partial<DocumentVersion>;
        Update: Partial<DocumentVersion>;
      };
      document_permissions: {
        Row: DocumentPermission;
        Insert: Partial<DocumentPermission>;
        Update: Partial<DocumentPermission>;
      };
      audit_events: {
        Row: AuditEvent;
        Insert: Partial<AuditEvent>;
        Update: Partial<AuditEvent>;
      };
      audit_chain_heads: {
        Row: {
          chain_id: string;
          last_sequence: number;
          last_hash: string;
          updated_at: string;
        };
        Insert: { chain_id: string; last_sequence: number; last_hash: string };
        Update: { last_sequence?: number; last_hash?: string; updated_at?: string };
      };
      security_alerts: {
        Row: SecurityAlert;
        Insert: Partial<SecurityAlert>;
        Update: Partial<SecurityAlert>;
      };
      organisation_settings: {
        Row: OrganisationSettings;
        Insert: Partial<OrganisationSettings>;
        Update: Partial<OrganisationSettings>;
      };
    };
    Functions: {
      insert_audit_event: {
        Args: {
          p_actor_id?: string | null;
          p_action: string;
          p_document_id?: string | null;
          p_target_user_id?: string | null;
          p_outcome?: string;
          p_request_id?: string;
          p_metadata?: Record<string, unknown>;
          p_chain_id?: string;
        };
        Returns: string;
      };
      verify_audit_chain: {
        Args: { p_chain_id?: string };
        Returns: AuditChainVerification;
      };
      list_all_users: {
        Args: Record<string, never>;
        Returns: Profile[];
      };
      update_user_role_status: {
        Args: {
          p_target_user_id: string;
          p_role?: string | null;
          p_status?: string | null;
        };
        Returns: Profile[];
      };
    };
  };
}
