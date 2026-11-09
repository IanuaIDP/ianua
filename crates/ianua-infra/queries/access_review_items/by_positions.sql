-- Hydrates only positions selected by a bounded review item page.
SELECT review_id, position, holder_kind, holder_id, choice,
       reviewer_kind, reviewer_id, reviewer_person,
       suggested_choice, suggested_reason
FROM access_review_items
WHERE tenant_id = $1 AND review_id = $2 AND position = ANY($3::bigint[])
ORDER BY position
