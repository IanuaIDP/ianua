-- The notifications context in a tenant's own database: each tenant user's
-- inbox, and the channel each of them chose per category. Both live with
-- the tenant, so they move with it and go with its purge.

-- A tenant user's notifications, one row per notification in one inbox.
-- The category is kept beside the event type it comes from, so a list can
-- filter and sort by it from an index; a row whose two disagree is refused
-- when it is read.
CREATE TABLE tenant_notifications (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event_type text NOT NULL,
    category text NOT NULL,
    -- How urgent: 0 info, 1 warning, 2 critical, so a list by severity runs
    -- by urgency.
    severity smallint NOT NULL,
    title text NOT NULL,
    body text,
    -- no foreign key: the record a notification is about can be of any kind,
    -- and the notice stays readable after that record is gone.
    resource_id uuid,
    reach text NOT NULL,
    read boolean NOT NULL,
    created_at timestamptz NOT NULL,
    -- A notification sits in one user's inbox and goes with their account.
    CONSTRAINT tenant_notifications_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT tenant_notifications_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT tenant_notifications_severity_known
        CHECK (severity BETWEEN 0 AND 2),
    CONSTRAINT tenant_notifications_reach_known
        CHECK (reach IN ('by_rights', 'own_account', 'addressed')),
    CONSTRAINT tenant_notifications_title_fits
        CHECK (char_length(title) BETWEEN 1 AND 200)
);

ALTER TABLE tenant_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_notifications
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'))
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's inbox by when, by severity and by category, each the order a
-- list can ask for; the first also leads the link to the user.
CREATE INDEX tenant_notifications_by_created
    ON tenant_notifications (tenant_id, user_id, created_at, id);
CREATE INDEX tenant_notifications_by_severity
    ON tenant_notifications (tenant_id, user_id, severity, id);
CREATE INDEX tenant_notifications_by_category
    ON tenant_notifications (tenant_id, user_id, category, id);
-- A user's unread notifications, newest first, and how many there are.
CREATE INDEX tenant_notifications_unread
    ON tenant_notifications (tenant_id, user_id, created_at, id) WHERE NOT read;
-- A tenant's notifications by age, for the purge of those past their keeping.
CREATE INDEX tenant_notifications_by_age
    ON tenant_notifications (tenant_id, created_at);

-- The channel a tenant user chose for one category. A category with no row
-- reaches them in the app.
CREATE TABLE notification_preferences (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    category text NOT NULL,
    channel text NOT NULL,
    PRIMARY KEY (tenant_id, user_id, category),
    -- A choice is one user's and goes with their account.
    CONSTRAINT notification_preferences_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT notification_preferences_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT notification_preferences_channel_known
        CHECK (channel IN ('in_app', 'in_app_and_email', 'disabled'))
);

ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON notification_preferences
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'))
    WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Every choice of the tenant for one category, read at once by the fan-out.
CREATE INDEX notification_preferences_by_category
    ON notification_preferences (tenant_id, category);
