-- Whether a user of a tenant has a confirmed second factor. It names only
-- the columns the gateway's role may read, never the factor's secret.
SELECT EXISTS (
    SELECT 1 FROM mfa_enrollments
    WHERE tenant_id = $1 AND user_id = $2 AND status = 'verified'
) AS "holds!"
