-- Changes only one existing decision while the caller holds its review lock.
UPDATE access_review_items
SET choice = $4, reviewer_kind = $5, reviewer_id = $6, reviewer_person = $7
WHERE tenant_id = $1 AND review_id = $2 AND position = $3
