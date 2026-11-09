-- Forgets the DPoP proofs one tenant saw that expired by the given time:
-- each would be refused as too old anyway.
DELETE FROM oauth_dpop_proofs
WHERE tenant_id = $1 AND expires_at <= $2
