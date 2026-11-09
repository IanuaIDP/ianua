-- Every separation rule of a tenant, oldest first.
SELECT id, name, first_role_id, second_role_id, created_at
FROM separation_rules
WHERE tenant_id = $1
ORDER BY created_at, id
