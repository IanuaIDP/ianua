-- Keeps a group of linked accounts: a new one is added; a known one has
-- nothing that changes, since its organization, address and creation time
-- are fixed. A new group under an address another group holds is refused
-- by the unique key.
INSERT INTO org_linked_identities (id, organization_id, email, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO NOTHING
