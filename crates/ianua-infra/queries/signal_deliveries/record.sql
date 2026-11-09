-- Records a signal sent to a stream of the tenant. The stream is looked up
-- within the tenant, so a stream of another tenant records nothing.
INSERT INTO signal_deliveries
    (id, tenant_id, stream_id, signal_id, signal_type, status, response_code, duration_ms,
     attempt_number, attempted_at)
SELECT $3::uuid, streams.tenant_id, streams.id, $4::uuid, $5::text, $6::text, $7::integer,
       $8::bigint, $9::smallint, $10::timestamptz
FROM signal_streams streams
WHERE streams.tenant_id = $1 AND streams.id = $2
