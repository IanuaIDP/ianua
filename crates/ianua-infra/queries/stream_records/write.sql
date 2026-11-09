-- Adds a tenant's stream connection records in one statement, each with
-- who was named on it, what was decided and how much moved.
INSERT INTO stream_records
    (id, tenant_id, stream_route_id, listen_port, client_address, server_name, caller,
     caller_id, decision, reason, backend, bytes_to_backend, bytes_to_client, duration_ms,
     occurred_at)
SELECT added.id, $1, added.stream_route_id, added.listen_port, added.client_address,
       added.server_name, added.caller, added.caller_id, added.decision, added.reason,
       added.backend, added.bytes_to_backend, added.bytes_to_client, added.duration_ms,
       added.occurred_at
FROM UNNEST($2::uuid[], $3::uuid[], $4::integer[], $5::text[], $6::text[], $7::text[],
            $8::uuid[], $9::text[], $10::text[], $11::text[], $12::bigint[], $13::bigint[],
            $14::integer[], $15::timestamptz[])
    AS added (id, stream_route_id, listen_port, client_address, server_name, caller, caller_id,
              decision, reason, backend, bytes_to_backend, bytes_to_client, duration_ms,
              occurred_at)
ON CONFLICT DO NOTHING
