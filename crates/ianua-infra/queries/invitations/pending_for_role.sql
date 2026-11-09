-- How many of a tenant's invitations still pending give the given role.
SELECT count(*) AS "count!"
FROM invitations
WHERE tenant_id = $1 AND role_id = $2 AND status = 'pending'
