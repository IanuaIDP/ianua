-- Reads the named holders' items in one go through the tenant/review/holder
-- unique key; a holder the review does not list is left out.
SELECT i.review_id, i.position, i.holder_kind, i.holder_id, i.choice,
       i.reviewer_kind, i.reviewer_id, i.reviewer_person,
       i.suggested_choice, i.suggested_reason
FROM access_review_items i
JOIN UNNEST($3::text[], $4::uuid[]) AS h(kind, id)
    ON i.holder_kind = h.kind AND i.holder_id = h.id
WHERE i.tenant_id = $1 AND i.review_id = $2
ORDER BY i.position
