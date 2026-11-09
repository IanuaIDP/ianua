-- Adds a tenant's audit records to its chain in one statement, each with
-- its place, the link before it and its own hash. A record is only ever
-- added, never written again.
INSERT INTO audit_records
    (tenant_id, id, seq, organization_id, actor, actor_kind, actor_id, event_type, target_id,
     ip_address, user_agent, payload, acted_through, through_operator_id, through_admin_id,
     as_user_id, support_impersonation_id, occurred_at, prev_hash, entry_hash,
     through_execution_id)
SELECT $1, added.id, added.seq, added.organization_id, added.actor, added.actor_kind,
       added.actor_id, added.event_type, added.target_id, added.ip_address, added.user_agent,
       added.payload, added.acted_through, added.through_operator_id, added.through_admin_id,
       added.as_user_id, added.support_impersonation_id, added.occurred_at, added.prev_hash,
       added.entry_hash, added.through_execution_id
FROM UNNEST($2::uuid[], $3::bigint[], $4::uuid[], $5::text[], $6::text[], $7::uuid[],
            $8::text[], $9::text[], $10::text[], $11::text[], $12::jsonb[], $13::text[],
            $14::uuid[], $15::uuid[], $16::uuid[], $17::uuid[], $18::timestamptz[],
            $19::bytea[], $20::bytea[], $21::uuid[])
    AS added (id, seq, organization_id, actor, actor_kind, actor_id, event_type, target_id,
              ip_address, user_agent, payload, acted_through, through_operator_id,
              through_admin_id, as_user_id, support_impersonation_id, occurred_at, prev_hash,
              entry_hash, through_execution_id)
