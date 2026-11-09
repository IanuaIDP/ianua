-- A stretch of a tenant's chain after the given place, oldest first, with
-- every column its hash covers.
SELECT id, seq, organization_id, actor, actor_kind, actor_id, event_type, target_id,
       ip_address, user_agent, payload, acted_through, through_operator_id, through_admin_id,
       as_user_id, support_impersonation_id, through_execution_id, occurred_at, prev_hash,
       entry_hash
FROM audit_records
WHERE tenant_id = $1 AND seq > $2
ORDER BY seq
LIMIT $3
