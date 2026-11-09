-- What a check of an organization member's reach into a tenant reads of
-- them: who they are, whose member, in what role and status. Nothing of
-- how they sign in, so the gateway's role may read it.
SELECT id, organization_id, role, status
FROM org_users
WHERE id = $1
