-- Keeps a service, and the hosts its sign-in answers on or its own cookie
-- is set on, in one statement: a host another service of the tenant holds,
-- or a name another has, refuses the whole write. Hosts the service no
-- longer names are released; hosts it already holds are kept. A new one is
-- added, a known one of the same tenant takes the new values. Its tenant
-- and creation time never change.
WITH released AS (
    DELETE FROM service_sign_in_hosts
    WHERE tenant_id = $2 AND service_id = $1 AND host <> ALL($12::text[])
),
claimed AS (
    INSERT INTO service_sign_in_hosts (tenant_id, host, service_id)
    SELECT $2, wanted.host, $1
    FROM UNNEST($12::text[]) AS wanted (host)
    WHERE NOT EXISTS (
        SELECT 1
        FROM service_sign_in_hosts held
        WHERE held.tenant_id = $2 AND held.host = wanted.host AND held.service_id = $1
    )
)
INSERT INTO services
    (id, tenant_id, name, upstream, health_check, app_sign_in, accepts_sign_in_of,
     sign_in_delivery, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    upstream = EXCLUDED.upstream,
    health_check = EXCLUDED.health_check,
    app_sign_in = EXCLUDED.app_sign_in,
    accepts_sign_in_of = EXCLUDED.accepts_sign_in_of,
    sign_in_delivery = EXCLUDED.sign_in_delivery,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE services.tenant_id = EXCLUDED.tenant_id
