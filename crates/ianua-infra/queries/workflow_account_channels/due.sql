-- Up to a page of the live channels that lapse before a moment, the soonest
-- first, in whichever tenants the read may see.
SELECT tenant_id, id
FROM workflow_account_channels
WHERE status = 'live' AND lapses_at IS NOT NULL AND lapses_at < $1
ORDER BY lapses_at, id
LIMIT $2
