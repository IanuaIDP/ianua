-- Hands out the logout request a tenant sent under the given ID and
-- forgets it in the same step, so its answer is taken once. Whether the
-- answer came in time is the request's own rule, so a late one is handed
-- out too.
DELETE FROM sent_logout_requests
WHERE tenant_id = $1 AND id = $2
RETURNING id, peer, destination, name_id_format, name_id, session_index, sent_at,
          expires_at
