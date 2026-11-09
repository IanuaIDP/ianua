-- The offer of one domain by the giving tenant, if it made one.
SELECT tenant_id, domain, to_tenant_id, offered_at, accepted_at
FROM domain_handover_offers
WHERE tenant_id = $1 AND domain = $2
