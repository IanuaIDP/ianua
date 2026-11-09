-- The services of one tenant with the given ids.
SELECT id, name, upstream, health_check, app_sign_in, accepts_sign_in_of,
       sign_in_delivery, status, created_at, updated_at
FROM services
WHERE tenant_id = $1 AND id = ANY($2)
