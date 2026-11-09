-- Adds a tenant's request records in one statement, each with what the
-- proxy observed and decided. The levels found on a request arrive as one
-- comma-joined text and are kept as a list.
--
-- A second write of a request's record is how a later close reaches it:
-- only the close columns are taken from it, and only the first close is
-- kept, so writing a record again changes nothing else.
INSERT INTO proxy_request_records
    (tenant_id, correlation_id, principal, principal_id, delegation_id, on_behalf_kind,
     on_behalf_id, consumer_credential, person_id, route_id, service_id, ip_address, method,
     path, outcome, status, reason, decided_by, decided_by_stage_id, rule, duration_ms,
     classification, occurred_at, policy_version, closed_reason, closed_at)
SELECT $1, added.correlation_id, added.principal, added.principal_id, added.delegation_id,
       added.on_behalf_kind, added.on_behalf_id, added.consumer_credential, added.person_id,
       added.route_id, added.service_id, added.ip_address, added.method, added.path,
       added.outcome, added.status, added.reason, added.decided_by, added.decided_by_stage_id,
       added.rule, added.duration_ms, string_to_array(added.classification, ','),
       added.occurred_at, added.policy_version, added.closed_reason, added.closed_at
FROM UNNEST($2::uuid[], $3::text[], $4::uuid[], $5::uuid[], $6::text[], $7::uuid[],
            $8::text[], $9::uuid[], $10::uuid[], $11::uuid[], $12::text[], $13::text[],
            $14::text[], $15::text[], $16::smallint[], $17::text[], $18::text[], $19::uuid[],
            $20::text[], $21::integer[], $22::text[], $23::timestamptz[], $24::bigint[],
            $25::text[], $26::timestamptz[])
    AS added (correlation_id, principal, principal_id, delegation_id, on_behalf_kind,
              on_behalf_id, consumer_credential, person_id, route_id, service_id, ip_address,
              method, path, outcome, status, reason, decided_by, decided_by_stage_id, rule,
              duration_ms, classification, occurred_at, policy_version, closed_reason,
              closed_at)
ON CONFLICT (correlation_id) DO UPDATE
    SET closed_reason = COALESCE(proxy_request_records.closed_reason, EXCLUDED.closed_reason),
        closed_at = COALESCE(proxy_request_records.closed_at, EXCLUDED.closed_at)
