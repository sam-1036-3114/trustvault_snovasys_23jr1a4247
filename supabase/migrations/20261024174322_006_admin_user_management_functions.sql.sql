/*
# Admin user management functions

## Overview
Migration 004 revoked broad UPDATE on profiles from authenticated, only
allowing UPDATE on display_name. This is correct for preventing privilege
escalation, but admins need to update role and status for user management.
This migration creates SECURITY DEFINER functions for:

1. list_all_users — admin-only function to list all users including suspended
2. update_user_role_status — admin-only function to update a user's role/status

## Security
- Both functions check that the caller (auth.uid()) has role = 'admin'
- Functions are SECURITY DEFINER so they run with elevated privileges
- EXECUTE is revoked from PUBLIC/anon, granted only to authenticated
- Admins cannot modify their own role (prevents self-escalation or self-demotion)
- Role is validated against the CHECK constraint values
*/

CREATE OR REPLACE FUNCTION list_all_users()
RETURNS TABLE(
  out_id uuid,
  out_email text,
  out_display_name text,
  out_role text,
  out_status text,
  out_created_at timestamptz,
  out_updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'
  ) THEN
    RAISE EXCEPTION 'Administrator access required';
  END IF;

  RETURN QUERY
  SELECT p.id, p.email, p.display_name, p.role, p.status, p.created_at, p.updated_at
  FROM profiles p
  ORDER BY p.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION list_all_users FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION list_all_users TO authenticated;

CREATE OR REPLACE FUNCTION update_user_role_status(
  p_target_user_id uuid,
  p_role text DEFAULT NULL,
  p_status text DEFAULT NULL
)
RETURNS TABLE(
  out_id uuid,
  out_email text,
  out_display_name text,
  out_role text,
  out_status text,
  out_created_at timestamptz,
  out_updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'
  ) THEN
    RAISE EXCEPTION 'Administrator access required';
  END IF;

  IF p_target_user_id = auth.uid() THEN
    RAISE EXCEPTION 'Cannot modify your own account';
  END IF;

  IF p_role IS NOT NULL AND p_role NOT IN ('admin', 'owner', 'viewer') THEN
    RAISE EXCEPTION 'Invalid role value';
  END IF;

  IF p_status IS NOT NULL AND p_status NOT IN ('active', 'suspended') THEN
    RAISE EXCEPTION 'Invalid status value';
  END IF;

  UPDATE profiles
  SET
    role = COALESCE(p_role, role),
    status = COALESCE(p_status, status)
  WHERE id = p_target_user_id;

  RETURN QUERY
  SELECT p.id, p.email, p.display_name, p.role, p.status, p.created_at, p.updated_at
  FROM profiles p
  WHERE p.id = p_target_user_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION update_user_role_status FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION update_user_role_status TO authenticated;
