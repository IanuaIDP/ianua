-- How many roles of a tenant hold a permission of their own naming the
-- given resource type key.
SELECT count(*) AS "count!"
FROM roles r
WHERE r.tenant_id = $1
  AND EXISTS (
      SELECT 1
      FROM unnest(r.custom_permissions) AS held (permission)
      WHERE split_part(held.permission, ':', 1) = $2
  )
