-- The notifications context in the platform database: the inboxes of
-- operators and organization members, the channels they chose, and the
-- places outside the app an organization's notifications go to. None of it
-- belongs to a tenant, so none of it moves with one.

-- An operator's notifications, one row per notification in one inbox. The
-- category is kept beside the event type it comes from; a row whose two
-- disagree is refused when it is read.
CREATE TABLE platform_notifications (
    id uuid PRIMARY KEY,
    -- A notification sits in one operator's inbox and goes with them.
    operator_id uuid NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
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
    CONSTRAINT platform_notifications_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT platform_notifications_severity_known
        CHECK (severity BETWEEN 0 AND 2),
    CONSTRAINT platform_notifications_reach_known
        CHECK (reach IN ('by_rights', 'own_account')),
    CONSTRAINT platform_notifications_title_fits
        CHECK (char_length(title) BETWEEN 1 AND 200)
);

-- An operator's inbox in each order a list can ask for; the first also
-- leads the link to the operator.
CREATE INDEX platform_notifications_by_created
    ON platform_notifications (operator_id, created_at, id);
CREATE INDEX platform_notifications_by_severity
    ON platform_notifications (operator_id, severity, id);
CREATE INDEX platform_notifications_by_category
    ON platform_notifications (operator_id, category, id);
-- An operator's unread notifications, newest first, and how many there are.
CREATE INDEX platform_notifications_unread
    ON platform_notifications (operator_id, created_at, id) WHERE NOT read;
-- Every operator's notifications by age, for the purge of those past their
-- keeping.
CREATE INDEX platform_notifications_by_age
    ON platform_notifications (created_at);

-- An organization member's notifications, one row per notification in one
-- inbox, kept as an operator's are.
CREATE TABLE org_notifications (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    org_user_id uuid NOT NULL,
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
    -- A notification sits in one member's inbox, in their organization, and
    -- goes with the member.
    CONSTRAINT org_notifications_member_fkey FOREIGN KEY (organization_id, org_user_id)
        REFERENCES org_users (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT org_notifications_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT org_notifications_severity_known
        CHECK (severity BETWEEN 0 AND 2),
    CONSTRAINT org_notifications_reach_known
        CHECK (reach IN ('by_rights', 'own_account')),
    CONSTRAINT org_notifications_title_fits
        CHECK (char_length(title) BETWEEN 1 AND 200)
);

-- A member's inbox in each order a list can ask for; the first also leads
-- the link to the member.
CREATE INDEX org_notifications_by_created
    ON org_notifications (organization_id, org_user_id, created_at, id);
CREATE INDEX org_notifications_by_severity
    ON org_notifications (organization_id, org_user_id, severity, id);
CREATE INDEX org_notifications_by_category
    ON org_notifications (organization_id, org_user_id, category, id);
-- A member's unread notifications, newest first, and how many there are.
CREATE INDEX org_notifications_unread
    ON org_notifications (organization_id, org_user_id, created_at, id) WHERE NOT read;
-- Every member's notifications by age, for the purge of those past their
-- keeping.
CREATE INDEX org_notifications_by_age
    ON org_notifications (created_at);

-- The channel an organization member chose for one category. A category
-- with no row reaches them in the app.
CREATE TABLE org_notification_preferences (
    organization_id uuid NOT NULL,
    org_user_id uuid NOT NULL,
    category text NOT NULL,
    channel text NOT NULL,
    PRIMARY KEY (organization_id, org_user_id, category),
    -- A choice is one member's and goes with them.
    CONSTRAINT org_notification_preferences_member_fkey FOREIGN KEY (organization_id, org_user_id)
        REFERENCES org_users (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT org_notification_preferences_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT org_notification_preferences_channel_known
        CHECK (channel IN ('in_app', 'in_app_and_email', 'disabled'))
);

-- Every member's choice for one category, read at once by the fan-out.
CREATE INDEX org_notification_preferences_by_category
    ON org_notification_preferences (organization_id, category);

-- The channel an operator chose for one category. A category with no row
-- reaches them in the app.
CREATE TABLE operator_notification_preferences (
    -- A choice is one operator's and goes with them.
    operator_id uuid NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    category text NOT NULL,
    channel text NOT NULL,
    PRIMARY KEY (operator_id, category),
    CONSTRAINT operator_notification_preferences_category_known
        CHECK (category IN ('identity', 'crypto', 'oauth', 'authorization', 'federation',
                            'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                            'authentication', 'organization', 'tenant', 'agents', 'consumers',
                            'messaging', 'domains', 'mtls', 'scim', 'classification', 'policy',
                            'audit', 'workflows')),
    CONSTRAINT operator_notification_preferences_channel_known
        CHECK (channel IN ('in_app', 'in_app_and_email', 'disabled'))
);

-- Every operator's choice for one category, read at once by the fan-out.
CREATE INDEX operator_notification_preferences_by_category
    ON operator_notification_preferences (category);

-- The places outside the app an organization's notifications go to: a
-- Slack or Teams channel, whose sealed address is the key that posts to it,
-- or a webhook of the organization's own, with the sealed secret its posts
-- are signed with.
CREATE TABLE org_notification_destinations (
    id uuid PRIMARY KEY,
    -- A destination is its organization's, and goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL,
    hook text,
    url text,
    signing_secret text,
    categories text[] NOT NULL,
    minimum_severity text NOT NULL,
    state text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT org_notification_destinations_kind_known
        CHECK (kind IN ('slack', 'teams', 'webhook')),
    CONSTRAINT org_notification_destinations_endpoint_fits_kind
        CHECK ((kind IN ('slack', 'teams')) = (hook IS NOT NULL)
           AND (kind = 'webhook') = (url IS NOT NULL)
           AND (kind = 'webhook') = (signing_secret IS NOT NULL)),
    CONSTRAINT org_notification_destinations_categories_known
        CHECK (categories <@ ARRAY['identity', 'crypto', 'oauth', 'authorization', 'federation',
                                   'routing', 'pipeline', 'signals', 'webhooks', 'branding',
                                   'authentication', 'organization', 'tenant', 'agents',
                                   'consumers', 'messaging', 'domains', 'mtls', 'scim',
                                   'classification', 'policy', 'audit', 'workflows']
           AND cardinality(categories) >= 1),
    CONSTRAINT org_notification_destinations_severity_known
        CHECK (minimum_severity IN ('info', 'warning', 'critical')),
    CONSTRAINT org_notification_destinations_state_known
        CHECK (state IN ('active', 'paused')),
    CONSTRAINT org_notification_destinations_changed_after_created
        CHECK (updated_at >= created_at)
);

-- An organization's destinations, oldest first; also the link to it.
CREATE INDEX org_notification_destinations_of_organization
    ON org_notification_destinations (organization_id, created_at, id);
