-- Keeps an organization's connection to one cloud: a new one is added with
-- the external id it was begun with, a known one takes its new standing.
-- Its organization, cloud, external id and when it was begun never change.
INSERT INTO org_cloud_accounts
    (organization_id, provider, external_id_sealed, state, credential_sealed, checked_at,
     verified_identity, failure_reason, bound_identity, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (organization_id, provider) DO UPDATE SET
    state = EXCLUDED.state,
    credential_sealed = EXCLUDED.credential_sealed,
    checked_at = EXCLUDED.checked_at,
    verified_identity = EXCLUDED.verified_identity,
    failure_reason = EXCLUDED.failure_reason,
    bound_identity = EXCLUDED.bound_identity,
    updated_at = EXCLUDED.updated_at
