-- Hands out the OIDC sign-in of a tenant kept under the given state and
-- forgets it in the same step, so a state is used once. A sign-in whose
-- time ran out by the given time is not handed out.
DELETE FROM oidc_flows
WHERE tenant_id = $1 AND state_hash = sha256(convert_to($2, 'UTF8')) AND lapses_at > $3
RETURNING connection_id, nonce, sealed_pkce_verifier, redirect_uri, binding_hash,
          dashboard_hash
