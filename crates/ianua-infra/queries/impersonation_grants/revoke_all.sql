-- Revokes every grant of an operator still unrevoked, in every tenant, and
-- counts them.
WITH revoked AS (
    UPDATE impersonation_grants
    SET revoked_at = $2
    WHERE operator_id = $1 AND revoked_at IS NULL
    RETURNING tenant_id
)
SELECT count(*) AS "revoked!" FROM revoked
