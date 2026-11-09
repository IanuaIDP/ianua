-- Keeps a mailed link: a new one is added, a known one of the same purpose
-- takes when it was used, only while it is still unused, so of two
-- requests following one link together only one changes the row. Its
-- member, address, purpose and times never change, and a use is never
-- undone.
INSERT INTO org_tokens
    (token_hash, purpose, org_user_id, sent_to, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (token_hash) DO UPDATE SET
    consumed_at = EXCLUDED.consumed_at
WHERE org_tokens.purpose = EXCLUDED.purpose AND org_tokens.consumed_at IS NULL
