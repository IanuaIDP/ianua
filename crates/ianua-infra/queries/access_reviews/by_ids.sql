-- The access reviews of a tenant with the given ids.
SELECT id, name, scope, scope_id, reviewer_kinds, reviewer_ids, reviewer_persons, due,
       unanswered, status, started_at, holder_count, pending_count, remove_count
FROM access_reviews
WHERE tenant_id = $1 AND id = ANY($2)
