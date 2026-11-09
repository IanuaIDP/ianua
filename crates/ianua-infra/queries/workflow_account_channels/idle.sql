-- Up to a page of the channels the platform registered, unchanged since
-- before a moment, that no live registration waits on, in whichever tenants
-- the read may see.
SELECT channel.tenant_id, channel.id
FROM workflow_account_channels AS channel
WHERE channel.setup = 'registered'
    AND channel.updated_at < $1
    AND NOT EXISTS (
        SELECT 1
        FROM workflow_service_subscriptions AS registration
        WHERE registration.integration = channel.integration
            AND registration.route_key = channel.id::text
            AND registration.status = 'live'
    )
ORDER BY channel.updated_at, channel.id
LIMIT $2
