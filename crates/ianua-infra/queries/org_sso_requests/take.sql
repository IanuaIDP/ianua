-- Hands out the sign-in kept under the given key and forgets it in the same
-- step, so an answer is used once. A sign-in whose time ran out by the
-- given time is not handed out.
DELETE FROM org_sso_requests
WHERE key_kind = $1 AND key_hash = sha256(convert_to($2, 'UTF8')) AND lapses_at > $3
RETURNING organization_id, connection_id, binding_hash, tenant_slug, nonce,
          pkce_verifier, redirect_uri
