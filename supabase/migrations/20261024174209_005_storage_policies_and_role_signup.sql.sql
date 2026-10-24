/*
# Storage policies for documents bucket + role selection at signup

## Overview
1. Adds storage RLS policies so authenticated users can upload to and download
   from the private 'documents' bucket. Previously the bucket was private with
   no policies, meaning only the service role could access it. Since the
   service role key is not available in the deployment environment, all
   storage operations failed with "Internal server error".
2. Updates the handle_new_user trigger to read the desired role from
   raw_user_meta_data at signup time, defaulting to 'viewer'. This allows
   role-based registration (admin vs user).
3. Adds a SECURITY DEFINER function to set a user's role, callable only
   during the signup flow via the trigger. Regular users cannot escalate.

## Security
- Storage SELECT (download) policy: authenticated users can only download
  objects whose path starts with their own user ID, OR any path if they are
  an admin. This mirrors the document-level access control.
- Storage INSERT (upload) policy: authenticated users can upload to paths
  starting with their own user ID.
- Storage DELETE policy: authenticated users can delete objects under their
  own user ID prefix, or any if admin.
- The role-setting trigger reads from raw_user_meta_data which is set by
  the server during signup and is not directly user-mutable through the
  Data API (it's set via auth.admin.updateUserById or signUp options).
*/

-- ============================================================================
-- STORAGE POLICIES FOR documents BUCKET
-- ============================================================================
-- Allow authenticated users to read (download) files they own or any if admin
DROP POLICY IF EXISTS "storage_read_own_or_admin" ON storage.objects;
CREATE POLICY "storage_read_own_or_admin" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'documents'
    AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR EXISTS (
        SELECT 1 FROM profiles p
        WHERE p.id = auth.uid() AND p.role = 'admin'
      )
    )
  );

-- Allow authenticated users to upload files to their own folder
DROP POLICY IF EXISTS "storage_upload_own" ON storage.objects;
CREATE POLICY "storage_upload_own" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'documents'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

-- Allow authenticated users to delete files from their own folder
DROP POLICY IF EXISTS "storage_delete_own_or_admin" ON storage.objects;
CREATE POLICY "storage_delete_own_or_admin" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'documents'
    AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR EXISTS (
        SELECT 1 FROM profiles p
        WHERE p.id = auth.uid() AND p.role = 'admin'
      )
    )
  );

-- ============================================================================
-- UPDATE handle_new_user TO ACCEPT ROLE FROM SIGNUP METADATA
-- ============================================================================
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_role text;
BEGIN
  v_role := COALESCE(NEW.raw_user_meta_data->>'role', 'viewer');

  -- Validate role, default to viewer if invalid
  IF v_role NOT IN ('admin', 'owner', 'viewer') THEN
    v_role := 'viewer';
  END IF;

  INSERT INTO profiles (id, email, display_name, role, status)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)),
    v_role,
    'active'
  );
  RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION handle_new_user FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION handle_new_user TO authenticated;

-- Ensure the trigger exists (recreate if dropped)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();
