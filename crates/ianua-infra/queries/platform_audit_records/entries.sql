-- The organization and platform audit records with the given ids. They
-- belong to no tenant, and no tenant user is named beside them.
SELECT id, NULL::uuid AS "tenant_id?", event_type, actor, actor_kind, actor_id, target_id,
       ip_address, payload, occurred_at, NULL::text AS "user_name?", NULL::text AS "user_email?",
       acted_through, through_operator_id, through_admin_id, as_user_id, support_impersonation_id,
       through_execution_id
FROM platform_audit_records
WHERE id = ANY($1)
