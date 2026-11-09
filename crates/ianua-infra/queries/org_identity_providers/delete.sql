-- Removes an organization's identity provider, and with it the sign-ins
-- still waiting on its answer.
DELETE FROM org_identity_providers
WHERE organization_id = $1 AND id = $2
