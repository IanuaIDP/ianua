-- The tenants whose id follows the given one, in id order.
SELECT id
FROM tenants
WHERE id > $1
ORDER BY id
LIMIT $2
