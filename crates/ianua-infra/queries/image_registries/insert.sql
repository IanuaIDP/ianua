-- Adds a registry just allowed. A host is on a tenant's list once, so a
-- second allowing of it is refused by its constraint.
INSERT INTO image_registries
    (id, tenant_id, host, login, username, password, allowed_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
