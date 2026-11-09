-- How many tenants an organization holds against its plan: every one not
-- deleted, archived ones too, since an archived tenant is restored without
-- a check.
SELECT count(*) AS "count!"
FROM tenants
WHERE organization_id = $1 AND status <> 'deleted'
