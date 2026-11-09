-- The separation rule of a tenant with the given id.
SELECT id, name, first_role_id, second_role_id, created_at
FROM separation_rules
WHERE tenant_id = $1 AND id = $2
