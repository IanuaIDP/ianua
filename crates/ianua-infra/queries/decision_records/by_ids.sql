-- The decision records of a tenant with the given ids.
SELECT id, asked_by, subject_kind, subject_id, verdict, policy_version, rule, basis, decided_at
FROM decision_records
WHERE tenant_id = $1 AND id = ANY($2)
