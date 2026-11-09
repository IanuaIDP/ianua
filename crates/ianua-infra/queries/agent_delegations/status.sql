-- Whether one delegation of a tenant still grants anything, read with
-- every delegation it draws its authority from: the one it was cut from,
-- those a minted one was cut from, those a token exchange derived it from,
-- and theirs in turn. A delegation that is gone reads with no status, and
-- a loop stored by mistake ends the walk. Each minted one carries the
-- status of the credential whose key minted it, so revoking that key ends
-- its token.
WITH RECURSIVE above (id) AS (
    SELECT $2::uuid
    UNION
    SELECT edge.source
    FROM above
    CROSS JOIN LATERAL (
        SELECT cut.parent_id AS source
        FROM agent_delegations cut
        WHERE cut.tenant_id = $1 AND cut.id = above.id AND cut.parent_id IS NOT NULL
        UNION ALL
        SELECT minted.source_id
        FROM delegation_sources minted
        WHERE minted.tenant_id = $1 AND minted.delegation_id = above.id
        UNION ALL
        SELECT derived.source_id
        FROM delegation_provenance derived
        WHERE derived.tenant_id = $1 AND derived.delegation_id = above.id
    ) AS edge
)
SELECT d.status AS "status?",
       d.minted_credential_id AS "minted_with?",
       c.status AS "key_status?"
FROM above
LEFT JOIN agent_delegations d ON d.tenant_id = $1 AND d.id = above.id
LEFT JOIN agent_credentials c ON c.tenant_id = $1 AND c.id = d.minted_credential_id
