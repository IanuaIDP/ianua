-- The holders of one role of a tenant with the given ids: who was given it
-- straight, with their kind, and the groups carrying it.
SELECT kind AS "kind!", principal_kind, holder_id AS "holder_id!"
FROM role_holders
WHERE tenant_id = $1 AND role_id = $2 AND holder_id = ANY($3)
