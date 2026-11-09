-- Updates only a locked review header, preserving its immutable holder snapshot.
UPDATE access_reviews
SET status = $3, pending_count = $4, remove_count = $5
WHERE tenant_id = $1 AND id = $2
