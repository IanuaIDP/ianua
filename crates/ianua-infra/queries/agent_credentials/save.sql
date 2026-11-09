-- Keeps an agent credential: a new one is added, a known one of the same
-- tenant takes the new values. Its tenant, its agent, its key and its
-- creation time never change. A key only moves on, active to rotated to
-- revoked: a copy read before a rotation or a revoke never moves it back,
-- never starts its grace again and never lengthens its life.
INSERT INTO agent_credentials
    (id, tenant_id, agent_id, kid, algorithm, public_key, status, rotated_at, attested_method,
     attested_subject, created_at, expires_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO UPDATE SET
    status = CASE
        WHEN agent_credentials.status = 'revoked' OR EXCLUDED.status = 'revoked' THEN 'revoked'
        WHEN agent_credentials.status = 'rotated' OR EXCLUDED.status = 'rotated' THEN 'rotated'
        ELSE EXCLUDED.status
    END,
    rotated_at = COALESCE(agent_credentials.rotated_at, EXCLUDED.rotated_at),
    attested_method = EXCLUDED.attested_method,
    attested_subject = EXCLUDED.attested_subject,
    expires_at = LEAST(agent_credentials.expires_at, EXCLUDED.expires_at),
    updated_at = GREATEST(EXCLUDED.updated_at, agent_credentials.updated_at)
WHERE agent_credentials.tenant_id = EXCLUDED.tenant_id
