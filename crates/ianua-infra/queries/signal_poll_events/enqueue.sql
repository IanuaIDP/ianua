-- Holds a token for a poll stream of the tenant until its receiver
-- acknowledges it. The stream is looked up within the tenant, so a stream
-- of another tenant holds nothing, and a token held already is held once.
INSERT INTO signal_poll_events (tenant_id, stream_id, jti, token)
SELECT streams.tenant_id, streams.id, $3::uuid, $4::text
FROM signal_streams streams
WHERE streams.tenant_id = $1 AND streams.id = $2
ON CONFLICT (tenant_id, stream_id, jti) DO NOTHING
