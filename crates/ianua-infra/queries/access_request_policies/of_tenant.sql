-- The longest a tenant lets its people ask for access, if it set a limit.
SELECT longest_seconds, updated_at
FROM access_request_policies
WHERE tenant_id = $1
