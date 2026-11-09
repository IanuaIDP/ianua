-- Adds a separation rule to a tenant.
INSERT INTO separation_rules (id, tenant_id, name, first_role_id, second_role_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
