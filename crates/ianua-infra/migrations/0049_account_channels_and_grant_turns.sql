-- An account's one address for a service's events, for a service that takes
-- one per account rather than one per workflow. Its id is in the address;
-- what proves a delivery is sealed by the app's secret sealer.
CREATE TABLE workflow_account_channels (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    account_id uuid NOT NULL,
    integration text NOT NULL,
    secret_sealed text NOT NULL,
    setup text NOT NULL,
    status text NOT NULL,
    remote text,
    lapses_at timestamp with time zone,
    history_cursor text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

-- When the service chose the secret itself, in a check of the address or in
-- its answer. Only the first one is kept.
ALTER TABLE workflow_service_subscriptions ADD COLUMN secret_given_at timestamp with time zone;

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_one_per_account UNIQUE (tenant_id, account_id);

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_pkey PRIMARY KEY (id);

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_account_id_fkey FOREIGN KEY (account_id) REFERENCES integration_accounts(id) ON DELETE CASCADE;

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_changed_after_opened CHECK ((updated_at >= created_at));

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_lapse_of_a_taken_one CHECK (((lapses_at IS NULL) OR (remote IS NOT NULL)));

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_setup_known CHECK ((setup = ANY (ARRAY['registered'::text, 'pasted_key'::text, 'token_from_service'::text])));

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_status_known CHECK ((status = ANY (ARRAY['registering'::text, 'awaiting_key'::text, 'awaiting_token'::text, 'awaiting_confirmation'::text, 'live'::text, 'lapsed'::text])));

-- The channels the renewal sweep looks at: live ones that lapse, the
-- soonest first.
CREATE INDEX workflow_account_channels_due ON workflow_account_channels USING btree (lapses_at, id) WHERE ((status = 'live'::text) AND (lapses_at IS NOT NULL));

-- The channels the idle sweep looks at: those the platform registered, the
-- longest unchanged first.
CREATE INDEX workflow_account_channels_idle ON workflow_account_channels USING btree (updated_at, id) WHERE (setup = 'registered'::text);

ALTER TABLE workflow_account_channels ENABLE ROW LEVEL SECURITY;

ALTER TABLE workflow_account_channels FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_rows ON workflow_account_channels AS PERMISSIVE FOR ALL TO public USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.platform_scope'::text, true) = 'on'::text)));
