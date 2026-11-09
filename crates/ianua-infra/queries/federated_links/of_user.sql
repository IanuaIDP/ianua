-- Every link an account of a tenant holds, one per connection, oldest
-- first.
SELECT connection_id, subject, user_id, linked_at, confirmed_at
FROM federated_links
WHERE tenant_id = $1 AND user_id = $2
ORDER BY linked_at, connection_id
