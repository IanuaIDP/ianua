-- Keeps one page of a loop's items a person opened. The same page of the
-- same opening opened again keeps the first time it was opened.
INSERT INTO workflow_approval_pages
    (tenant_id, execution_id, step, person, opening, first_item, item_count, opened_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, execution_id, step, person, opening, first_item, item_count)
    DO NOTHING
