-- Forgets the client assertions one tenant spent that expired by the given
-- time: none of them is taken any more.
DELETE FROM oauth_client_assertions
WHERE tenant_id = $1 AND expires_at <= $2
