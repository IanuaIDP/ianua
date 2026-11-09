-- Withdraw obsolete roots and roots whose tenant is no longer serving them.
DELETE FROM platform_certificates p
WHERE NOT (p.root = ANY($1::text[])) OR NOT EXISTS (
    SELECT 1 FROM tenants t WHERE t.id = p.tenant_id
    AND t.status IN ('active', 'provisioning') AND (NOT p.readable OR t.readable_address)
)
