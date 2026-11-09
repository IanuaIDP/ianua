-- Forgets up to a page of the deliveries noted before a moment, oldest
-- first, in whichever tenants the statement may see.
DELETE FROM workflow_service_deliveries
WHERE (tenant_id, subscription_id, delivery) IN (
    SELECT tenant_id, subscription_id, delivery FROM workflow_service_deliveries
    WHERE noted_at < $1
    ORDER BY noted_at
    LIMIT $2
)
