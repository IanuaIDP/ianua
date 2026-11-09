-- Every page one person opened of the items one loop of one run asked an
-- approval for, of any opening.
SELECT opening, first_item, item_count, opened_at
FROM workflow_approval_pages
WHERE tenant_id = $1 AND execution_id = $2 AND step = $3 AND person = $4
ORDER BY opened_at, first_item
