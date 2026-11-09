-- Records that the key of one thumbprint used a DPoP proof in one tenant,
-- kept until it expires, answering its id only when this statement was the
-- first use.
INSERT INTO oauth_dpop_proofs (tenant_id, thumbprint, jti, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, thumbprint, jti) DO NOTHING
RETURNING jti
