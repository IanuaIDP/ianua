-- Hands out the SAML sign-in request of a tenant kept under the given ID
-- and forgets it in the same step, so an answer is used once. A request
-- whose time ran out by the given time is not handed out.
DELETE FROM saml_requests
WHERE tenant_id = $1 AND request_id = $2 AND lapses_at > $3
RETURNING connection_id, binding_hash, dashboard_hash
