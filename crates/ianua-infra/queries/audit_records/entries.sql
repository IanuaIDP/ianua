-- The audit records with the given ids, of the given tenants or of any,
-- each with the name and address of the tenant user who acted, when one
-- did and is still there.
SELECT r.id, r.tenant_id AS "tenant_id?", r.event_type, r.actor, r.actor_kind, r.actor_id,
       r.target_id, r.ip_address, r.payload, r.occurred_at,
       u.display_name AS "user_name?", u.email AS "user_email?",
       r.acted_through, r.through_operator_id, r.through_admin_id, r.as_user_id,
       r.support_impersonation_id, r.through_execution_id
FROM audit_records r
LEFT JOIN users u
    ON u.tenant_id = r.tenant_id AND u.id = r.actor_id AND r.actor_kind = 'tenant_user'
WHERE ($1::uuid[] IS NULL OR r.tenant_id = ANY($1)) AND r.id = ANY($2)
