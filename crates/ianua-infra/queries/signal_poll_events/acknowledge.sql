-- Drops the tokens a poll stream of the tenant holds under the given ids,
-- once its receiver acknowledged them.
DELETE FROM signal_poll_events
WHERE tenant_id = $1 AND stream_id = $2 AND jti = ANY($3)
