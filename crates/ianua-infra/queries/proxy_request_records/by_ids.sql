-- The tenant's request records with the given correlation ids.
SELECT tenant_id, correlation_id, principal, principal_id, delegation_id, on_behalf_kind,
       on_behalf_id, consumer_credential, route_id, service_id, ip_address, method, path,
       outcome, status, reason, decided_by, decided_by_stage_id, rule, duration_ms,
       classification, occurred_at, policy_version, closed_reason, closed_at
FROM proxy_request_records
WHERE tenant_id = $1 AND correlation_id = ANY($2)
