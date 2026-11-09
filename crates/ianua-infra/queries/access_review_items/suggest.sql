-- Sets the suggestion beside each named position while the caller holds the
-- review lock; decisions are left as they are.
UPDATE access_review_items AS i
SET suggested_choice = s.choice, suggested_reason = s.reason
FROM UNNEST($3::bigint[], $4::text[], $5::text[]) AS s(position, choice, reason)
WHERE i.tenant_id = $1 AND i.review_id = $2 AND i.position = s.position
