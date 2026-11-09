-- Withdraws the links of one group to every tenant but the given ones.
DELETE FROM org_linked_identity_links
WHERE linked_identity_id = $1 AND tenant_id <> ALL($2)
