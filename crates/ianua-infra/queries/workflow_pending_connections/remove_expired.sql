-- Removes up to a page of every tenant's connections that ran out, oldest
-- first, in whichever tenants the statement may see.
DELETE FROM workflow_pending_connections
WHERE (tenant_id, id) IN (
    SELECT tenant_id, id FROM workflow_pending_connections
    WHERE expires_at <= $1
    ORDER BY expires_at
    LIMIT $2
)
