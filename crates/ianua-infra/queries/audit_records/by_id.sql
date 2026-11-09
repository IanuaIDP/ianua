-- One of a tenant's audit records, by its id.
SELECT id, organization_id, actor, event_type, target_id, ip_address, user_agent, payload,
       acted_through, through_operator_id, through_admin_id, as_user_id,
       support_impersonation_id, through_execution_id, occurred_at
FROM audit_records
WHERE tenant_id = $1 AND id = $2
