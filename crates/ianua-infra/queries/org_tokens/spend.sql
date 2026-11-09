-- Spends one mailed link of one purpose at the given time, only while it is
-- still unused: of two requests following one link together, only one
-- changes the row and learns it won.
UPDATE org_tokens
SET consumed_at = $3
WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL
