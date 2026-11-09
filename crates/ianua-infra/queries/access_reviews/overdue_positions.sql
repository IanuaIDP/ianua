-- Stable positions for a bounded overdue page, without holder hydration.
SELECT id, due
FROM access_reviews
WHERE tenant_id = $1 AND id = ANY($2)
