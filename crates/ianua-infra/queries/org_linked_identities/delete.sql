-- Removes the group an organization keeps under one address; its links go
-- with it.
DELETE FROM org_linked_identities
WHERE organization_id = $1 AND email = $2
