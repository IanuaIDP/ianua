-- The rule set a tenant classifies its response fields by.
SELECT id, rules, created_at, updated_at
FROM classification_rule_sets
WHERE tenant_id = $1
