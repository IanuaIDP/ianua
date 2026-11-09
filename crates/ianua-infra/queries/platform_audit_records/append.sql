-- Adds organization and platform audit records in one statement. A record
-- is only ever added, never written again.
INSERT INTO platform_audit_records
    (id, organization_id, actor, actor_kind, actor_id, event_type, target_id, ip_address,
     user_agent, payload, acted_through, through_operator_id, through_admin_id, as_user_id,
     support_impersonation_id, occurred_at, through_execution_id)
SELECT added.id, added.organization_id, added.actor, added.actor_kind, added.actor_id,
       added.event_type, added.target_id, added.ip_address, added.user_agent, added.payload,
       added.acted_through, added.through_operator_id, added.through_admin_id, added.as_user_id,
       added.support_impersonation_id, added.occurred_at, added.through_execution_id
FROM UNNEST($1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::uuid[], $6::text[],
            $7::text[], $8::text[], $9::text[], $10::jsonb[], $11::text[], $12::uuid[],
            $13::uuid[], $14::uuid[], $15::uuid[], $16::timestamptz[], $17::uuid[])
    AS added (id, organization_id, actor, actor_kind, actor_id, event_type, target_id,
              ip_address, user_agent, payload, acted_through, through_operator_id,
              through_admin_id, as_user_id, support_impersonation_id, occurred_at,
              through_execution_id)
