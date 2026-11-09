-- Deletes one registered domain of one tenant only while its claim is
-- still lapsed: never proved and registered by the first cutoff, or its
-- proof lost by the second. One proved meanwhile is kept.
DELETE FROM registered_domains
WHERE tenant_id = $1 AND id = $2
  AND ((verification_status = 'pending' AND created_at <= $3)
    OR (verification_status = 'failed' AND failed_at <= $4))
