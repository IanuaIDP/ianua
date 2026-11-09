-- How many notifications of a tenant user's inbox are not yet read and
-- show to them: those on their own account or sent to them by name, and
-- those in a category they may see.
SELECT count(*) AS "count!"
FROM tenant_notifications
WHERE tenant_id = $1 AND user_id = $2 AND NOT read
  AND (reach IN ('own_account', 'addressed') OR category = ANY($3))
