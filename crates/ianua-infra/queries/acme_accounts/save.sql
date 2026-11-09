-- Keeps the sealed credentials of the account held with one authority,
-- replacing any kept before; when it was first kept stays as it was.
INSERT INTO acme_accounts (directory_url, credentials_sealed, created_at, updated_at)
VALUES ($1, $2, $3, $3)
ON CONFLICT (directory_url) DO UPDATE SET
    credentials_sealed = EXCLUDED.credentials_sealed,
    updated_at = GREATEST(acme_accounts.updated_at, EXCLUDED.updated_at)
