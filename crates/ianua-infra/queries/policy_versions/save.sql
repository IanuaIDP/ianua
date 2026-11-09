-- Keeps one version of a tenant's access policy, inserting it or replacing
-- the row with its number. What it was started from never changes.
INSERT INTO policy_versions
    (tenant_id, version, status, based_on, based_on_version, default_action, rules,
     submitted_by_kind, submitted_by_id, submitted_by_person)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, version) DO UPDATE SET
    status = EXCLUDED.status,
    default_action = EXCLUDED.default_action,
    rules = EXCLUDED.rules,
    submitted_by_kind = EXCLUDED.submitted_by_kind,
    submitted_by_id = EXCLUDED.submitted_by_id,
    submitted_by_person = EXCLUDED.submitted_by_person
