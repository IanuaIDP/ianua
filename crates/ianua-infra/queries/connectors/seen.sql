-- Notes when the gateway last saw a link of one enrolled connector. A
-- later sighting already noted is kept, and one dated before the
-- enrollment, from a gateway whose clock runs behind, is dropped.
UPDATE connectors
SET last_seen_at = $3
WHERE tenant_id = $1
  AND id = $2
  AND enrolled_at <= $3
  AND (last_seen_at IS NULL OR last_seen_at < $3)
