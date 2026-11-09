-- Keeps a handover offer: a new one is added, one the giving tenant made
-- of the same domain before is replaced by it, and an accepted one is kept
-- spent.
INSERT INTO domain_handover_offers (tenant_id, domain, to_tenant_id, offered_at, accepted_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, domain) DO UPDATE SET
    to_tenant_id = EXCLUDED.to_tenant_id,
    offered_at = EXCLUDED.offered_at,
    accepted_at = EXCLUDED.accepted_at
