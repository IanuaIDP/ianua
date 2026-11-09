-- Removes the link of one purpose a tenant mailed with the given hash, in
-- one statement, so of two follows arriving together only one removes it.
DELETE FROM mailed_links
WHERE tenant_id = $1 AND purpose = $2 AND token_hash = $3
