-- Writes when the holder of a kept link last confirmed it, found by its
-- connection and account. Who it links and when it was made never change.
UPDATE federated_links
SET confirmed_at = $4
WHERE tenant_id = $1 AND connection_id = $2 AND user_id = $3
