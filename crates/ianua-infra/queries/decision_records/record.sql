-- Keeps the record of one decision of a tenant. A record is evidence: it
-- is written once and never changed.
INSERT INTO decision_records
    (id, tenant_id, asked_by, subject_kind, subject_id, verdict, policy_version, rule, basis,
     decided_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
