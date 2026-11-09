-- Keeps one evidence record per answer in a single atomic statement.
INSERT INTO decision_records
    (id, tenant_id, asked_by, subject_kind, subject_id, verdict, policy_version, rule, basis,
     decided_at)
SELECT kept.id, $2, kept.asked_by, kept.subject_kind, kept.subject_id, kept.verdict,
       kept.policy_version, kept.rule, kept.basis, kept.decided_at
FROM unnest($1::uuid[], $3::jsonb[], $4::text[], $5::uuid[], $6::text[],
            $7::integer[], $8::text[], $9::jsonb[], $10::timestamptz[])
    AS kept(id, asked_by, subject_kind, subject_id, verdict, policy_version, rule, basis,
            decided_at)
