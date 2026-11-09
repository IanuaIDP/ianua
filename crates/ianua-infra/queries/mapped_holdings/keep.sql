-- Keeps the record of what a connection's mapping gave an account of a
-- tenant; one kept already stays, its roles and groups written beside it.
INSERT INTO mapped_holdings (tenant_id, connection_id, user_id)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, connection_id, user_id) DO NOTHING
