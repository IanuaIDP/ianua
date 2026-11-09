-- Serializes decisions, cancellation and completion without loading holders.
SELECT id, name, scope, scope_id, reviewer_kinds, reviewer_ids, reviewer_persons, due,
       unanswered, status, started_at, holder_count, pending_count, remove_count
FROM access_reviews
WHERE tenant_id = $1 AND id = $2
FOR UPDATE
