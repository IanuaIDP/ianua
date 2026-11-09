-- The group of linked accounts an organization keeps under one address.
SELECT id, organization_id, email, created_at
FROM org_linked_identities
WHERE organization_id = $1 AND email = $2
