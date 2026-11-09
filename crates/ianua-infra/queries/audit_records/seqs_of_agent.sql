-- Which of the given places in the tenant's chain hold records the agent
-- made, in chain order.
SELECT seq
FROM audit_records
WHERE tenant_id = $1 AND actor_kind = $2 AND actor_id = $3 AND seq = ANY($4)
ORDER BY seq
