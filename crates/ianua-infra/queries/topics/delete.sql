-- Removes a topic of the tenant for good, with every subscription to it.
DELETE FROM topics
WHERE tenant_id = $1 AND id = $2
