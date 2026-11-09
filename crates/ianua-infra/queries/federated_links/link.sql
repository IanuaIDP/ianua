-- Keeps a new link. A subject or an account already linked on the
-- connection is refused by its constraint.
INSERT INTO federated_links (tenant_id, connection_id, subject, user_id, linked_at, confirmed_at)
VALUES ($1, $2, $3, $4, $5, $6)
