-- Records that a principal of a tenant holds a relation on a named
-- resource. Granting what it already holds changes nothing, and keeps who
-- granted it first.
INSERT INTO resource_grants
    (tenant_id, subject_kind, subject_id, relation, object_ref, granted_by_kind, granted_by_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, subject_kind, subject_id, relation, object_ref) DO NOTHING
