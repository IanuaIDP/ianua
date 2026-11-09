-- Notes one delivery to one registration, unless it was noted already; a
-- row is written only the first time.
INSERT INTO workflow_service_deliveries (tenant_id, subscription_id, delivery, noted_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, subscription_id, delivery) DO NOTHING
