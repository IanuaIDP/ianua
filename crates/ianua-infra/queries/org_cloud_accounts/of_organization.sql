-- Every connection an organization made, in the order it began them, their
-- secrets still sealed.
SELECT organization_id, provider, external_id_sealed, state, credential_sealed, checked_at,
    verified_identity, failure_reason, bound_identity, created_at, updated_at
FROM org_cloud_accounts
WHERE organization_id = $1
ORDER BY created_at, provider
