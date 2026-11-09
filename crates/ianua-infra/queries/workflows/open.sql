-- Keeps the workflow a version belongs to, with where it came from, when
-- its first version is drafted. A workflow already kept is left as it is.
INSERT INTO workflows (id, tenant_id, origin, flow_description)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO NOTHING
