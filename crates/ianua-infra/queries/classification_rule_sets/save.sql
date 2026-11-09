-- Keeps a tenant's rule set: a new one is added, the known one takes its
-- new rules. Its tenant and creation time never change.
INSERT INTO classification_rule_sets (id, tenant_id, rules, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    rules = EXCLUDED.rules,
    updated_at = EXCLUDED.updated_at
WHERE classification_rule_sets.tenant_id = EXCLUDED.tenant_id
