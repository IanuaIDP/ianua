-- The requested members' passkeys, preserving each member's creation order.
SELECT id, org_user_id, credential_id, public_key, sign_count,
       authenticator_type, attestation, name, last_used_at, created_at
FROM org_passkey_credentials
WHERE org_user_id = ANY($1::uuid[])
ORDER BY org_user_id, created_at, id
