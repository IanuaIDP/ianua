-- The authentication context: a tenant's sessions, passwords and their
-- resets, second factors and the codes sent for them, recovery codes,
-- passkeys and their ceremonies, trusted devices, failed sign-in counts,
-- where people signed in from, the one-time passes of a sign-in, and the
-- break-glass policy.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- Only what the domain hands over is kept: hashes of passwords, tokens and
-- codes, a sealed authenticator seed, a passkey's public key, never a
-- secret in clear text.

-- Signed-in sessions. A refresh makes a new session naming the one it
-- replaced.
CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    refresh_token_hash text NOT NULL,
    -- The session a refresh made this one from, or NULL for a sign-in. It
    -- keeps naming a parent the sweep has since deleted.
    -- no foreign key: a session keeps the name of the session it replaced after that one is purged
    parent_id uuid,
    -- What the client sent, or NULL when nobody observed it.
    ip_address text,
    user_agent text,
    auth_method text NOT NULL,
    -- The strongest second factor proved, or NULL for none yet.
    factor text,
    owed text NOT NULL,
    status text NOT NULL,
    -- The service whose app sign-in opened it, or NULL for the dashboard.
    app_service_id uuid,
    signed_in_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_active_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- The change of how the account signs in the session was kept
    -- through, or NULL for none.
    kept_through timestamptz,
    -- The trusted device the sign-in came from, when the browser presented
    -- the secret of a device its holder remembered, or NULL when it
    -- presented none. Every session a refresh carries on from it names the
    -- same device, and a device posture check at the gateway asks about it.
    -- Its foreign key follows trusted_devices below.
    signed_in_from uuid,
    CONSTRAINT sessions_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT sessions_refresh_token_key UNIQUE (tenant_id, refresh_token_hash),
    -- A session cannot outlive the account signed in to it.
    CONSTRAINT sessions_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    -- A session opened on an app's host is good on that app alone, so it
    -- ends with the service.
    CONSTRAINT sessions_app_service_fkey FOREIGN KEY (tenant_id, app_service_id)
        REFERENCES services (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sessions_auth_method_known
        CHECK (auth_method IN ('password', 'magic_link', 'passkey', 'saml', 'oidc')),
    CONSTRAINT sessions_factor_known
        CHECK (factor IN ('totp', 'email_code', 'sms_code', 'recovery_code', 'hardware_key',
                          'passkey', 'email_confirmation', 'provider_multi_factor',
                          'provider_hardware_key')),
    CONSTRAINT sessions_owed_known
        CHECK (owed IN ('not_owed', 'verify', 'enrol', 'confirm_by_email', 'confirm_then_enrol')),
    CONSTRAINT sessions_status_known
        CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT sessions_not_own_parent
        CHECK (parent_id IS NULL OR parent_id <> id),
    CONSTRAINT sessions_used_after_created
        CHECK (last_active_at >= created_at),
    CONSTRAINT sessions_expires_after_created
        CHECK (expires_at >= created_at),
    CONSTRAINT sessions_signed_in_before_created
        CHECK (signed_in_at <= created_at)
);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sessions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's sessions, newest first, and revoking them all.
CREATE INDEX sessions_of_user ON sessions (tenant_id, user_id, created_at, id);
-- Whether a refresh replaced a session.
CREATE INDEX sessions_by_parent ON sessions (tenant_id, parent_id);
-- The service a session was opened through, for the foreign key.
CREATE INDEX sessions_of_app_service ON sessions (tenant_id, app_service_id);
-- A presented refresh token is found by its digest alone, before the
-- tenant it belongs to is known, so the lookup needs a key of its own.
CREATE INDEX sessions_by_refresh_token ON sessions (refresh_token_hash);
-- Sessions that ran out, oldest first, and ended sessions by their last
-- use, for the purge.
CREATE INDEX sessions_by_expiry ON sessions (tenant_id, expires_at);
CREATE INDEX sessions_ended ON sessions (tenant_id, last_active_at) WHERE status = 'revoked';

-- The password of each account that has one, with who set it and when.
CREATE TABLE user_passwords (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    password_hash text NOT NULL,
    origin text NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    -- A password is part of the account and goes with it.
    CONSTRAINT user_passwords_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_passwords_origin_known
        CHECK (origin IN ('chosen_by_holder', 'set_by_admin'))
);

ALTER TABLE user_passwords ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_passwords FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON user_passwords
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The hashes of an account's retired passwords, so a new one cannot
-- repeat them.
CREATE TABLE password_history (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL,
    password_hash text NOT NULL,
    PRIMARY KEY (tenant_id, user_id, recorded_at),
    -- The history guards the account and goes with it.
    CONSTRAINT password_history_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON password_history
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Requests to reset a password, each with the hash of its mailed link.
CREATE TABLE password_resets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    initiator text NOT NULL,
    status text NOT NULL,
    completed_at timestamptz,
    token_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT password_resets_token_key UNIQUE (tenant_id, token_hash),
    -- A reset opens one account and means nothing once it is gone.
    CONSTRAINT password_resets_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT password_resets_initiator_known
        CHECK (initiator IN ('user', 'admin', 'system')),
    CONSTRAINT password_resets_status_known
        CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
    CONSTRAINT password_resets_completion_fits_status
        CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CONSTRAINT password_resets_expires_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT password_resets_completed_in_time
        CHECK (completed_at IS NULL OR (completed_at >= created_at AND completed_at < expires_at))
);

ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_resets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON password_resets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's requests, newest last: the latest one, and the pending ones to
-- expire.
CREATE INDEX password_resets_of_user ON password_resets (tenant_id, user_id, created_at, id);

-- An account's second factor: at most one enrollment each, of one kind.
CREATE TABLE mfa_enrollments (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    method text NOT NULL,
    -- An authenticator app's seed, sealed before it reaches here; NULL for
    -- every other kind.
    sealed_secret text,
    -- The number texted codes go to; NULL for every other kind.
    phone_number text,
    status text NOT NULL,
    verified_at timestamptz,
    -- The digest of the recovery codes handed out when it was confirmed.
    recovery_codes_hash text,
    disabled_at timestamptz,
    failed_attempts bigint NOT NULL,
    last_failed_at timestamptz,
    -- The latest code step accepted, so a code is never accepted twice.
    last_claimed_step bigint,
    enrolled_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    -- A factor is part of the account and goes with it.
    CONSTRAINT mfa_enrollments_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT mfa_enrollments_method_known
        CHECK (method IN ('totp', 'email_code', 'sms_code')),
    CONSTRAINT mfa_enrollments_status_known
        CHECK (status IN ('pending', 'verified', 'disabled')),
    CONSTRAINT mfa_enrollments_secret_fits_method
        CHECK ((method = 'totp') = (sealed_secret IS NOT NULL)),
    CONSTRAINT mfa_enrollments_phone_fits_method
        CHECK ((method = 'sms_code') = (phone_number IS NOT NULL)),
    CONSTRAINT mfa_enrollments_confirmation_whole
        CHECK ((verified_at IS NULL) = (recovery_codes_hash IS NULL)),
    CONSTRAINT mfa_enrollments_times_fit_status
        CHECK ((status = 'pending' AND verified_at IS NULL AND disabled_at IS NULL)
            OR (status = 'verified' AND verified_at IS NOT NULL AND disabled_at IS NULL)
            OR (status = 'disabled' AND disabled_at IS NOT NULL)),
    CONSTRAINT mfa_enrollments_failures_whole
        CHECK (failed_attempts >= 0 AND (failed_attempts = 0) = (last_failed_at IS NULL)),
    CONSTRAINT mfa_enrollments_confirmed_after_enrolled
        CHECK (verified_at >= enrolled_at),
    CONSTRAINT mfa_enrollments_disabled_after_enrolled
        CHECK (disabled_at >= enrolled_at),
    CONSTRAINT mfa_enrollments_step_known
        CHECK (last_claimed_step >= 0)
);

ALTER TABLE mfa_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mfa_enrollments
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The latest code mailed or texted for an account's second factor. A new
-- one replaces it, so only the latest counts.
CREATE TABLE mfa_sent_codes (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    -- When the factor the code was sent for was set up.
    enrolled_at timestamptz NOT NULL,
    method text NOT NULL,
    code_hash text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    wrong_tries smallint NOT NULL,
    spent_at timestamptz,
    PRIMARY KEY (tenant_id, user_id),
    -- A code proves the account's own factor and goes with the account.
    CONSTRAINT mfa_sent_codes_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT mfa_sent_codes_method_known
        CHECK (method IN ('email_code', 'sms_code')),
    CONSTRAINT mfa_sent_codes_sent_after_enrolled
        CHECK (issued_at >= enrolled_at),
    CONSTRAINT mfa_sent_codes_expires_after_issued
        CHECK (expires_at > issued_at),
    CONSTRAINT mfa_sent_codes_spent_in_time
        CHECK (spent_at IS NULL OR (spent_at >= issued_at AND spent_at < expires_at)),
    CONSTRAINT mfa_sent_codes_tries_counted
        CHECK (wrong_tries >= 0)
);

ALTER TABLE mfa_sent_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_sent_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mfa_sent_codes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An account's set of recovery codes: when it was made, one row per set.
CREATE TABLE recovery_code_sets (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    generated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    -- The set is part of the account and goes with it.
    CONSTRAINT recovery_code_sets_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE recovery_code_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_code_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON recovery_code_sets
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The codes of a set, each its own row, so spending one is one update that
-- only one sign-in can win.
CREATE TABLE recovery_codes (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash text NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (tenant_id, user_id, code_hash),
    -- A code belongs to its set and goes with it.
    CONSTRAINT recovery_codes_set_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES recovery_code_sets (tenant_id, user_id) ON DELETE CASCADE
);

ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON recovery_codes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An account's passkeys. A credential id names one passkey of a tenant,
-- since it is what a sign-in finds the passkey by.
CREATE TABLE passkey_credentials (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL,
    authenticator_type text NOT NULL,
    attestation text NOT NULL,
    name text NOT NULL,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT passkey_credentials_credential_key UNIQUE (tenant_id, credential_id),
    -- A passkey is part of the account and goes with it.
    CONSTRAINT passkey_credentials_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT passkey_credentials_authenticator_known
        CHECK (authenticator_type IN ('platform', 'cross_platform')),
    CONSTRAINT passkey_credentials_attestation_known
        CHECK (attestation IN ('unattested', 'hardware_key')),
    CONSTRAINT passkey_credentials_sign_count_fits
        CHECK (sign_count BETWEEN 0 AND 4294967295 AND (sign_count = 0 OR last_used_at IS NOT NULL)),
    CONSTRAINT passkey_credentials_used_after_created
        CHECK (last_used_at >= created_at)
);

ALTER TABLE passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON passkey_credentials
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's passkeys in the order they were added.
CREATE INDEX passkey_credentials_of_user
    ON passkey_credentials (tenant_id, user_id, created_at, id);

-- Passkey ceremonies in flight. One opened for a discoverable sign-in
-- names nobody yet.
CREATE TABLE passkey_ceremonies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- The account the ceremony was opened for, or NULL for a discoverable
    -- sign-in. A ceremony means nothing without its account.
    user_id uuid,
    purpose text NOT NULL,
    -- The verifier's opaque state between the challenge and the answer.
    state bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT passkey_ceremonies_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT passkey_ceremonies_purpose_known
        CHECK (purpose IN ('registration', 'authentication', 'discoverable_authentication')),
    CONSTRAINT passkey_ceremonies_subject_fits_purpose
        CHECK ((user_id IS NULL) = (purpose = 'discoverable_authentication')),
    CONSTRAINT passkey_ceremonies_expires_after_created
        CHECK (expires_at >= created_at),
    CONSTRAINT passkey_ceremonies_settled_in_time
        CHECK (consumed_at >= created_at AND consumed_at < expires_at)
);

ALTER TABLE passkey_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_ceremonies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON passkey_ceremonies
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The account a ceremony was opened for, for the foreign key.
CREATE INDEX passkey_ceremonies_of_user ON passkey_ceremonies (tenant_id, user_id);
-- The ceremonies never answered, by when they lapse, for the sweep.
CREATE INDEX passkey_ceremonies_unanswered ON passkey_ceremonies (tenant_id, expires_at)
    WHERE consumed_at IS NULL;

-- The devices people trust to skip their second factor.
CREATE TABLE trusted_devices (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    secret_hash text NOT NULL,
    device_name text NOT NULL,
    last_user_agent text NOT NULL,
    last_ip text NOT NULL,
    status text NOT NULL,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    -- Sessions name the device they signed in from with its tenant.
    CONSTRAINT trusted_devices_tenant_id_key UNIQUE (tenant_id, id),
    -- A device is trusted by the person who remembered it, and goes with
    -- their account.
    CONSTRAINT trusted_devices_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT trusted_devices_status_known
        CHECK (status IN ('trusted', 'revoked')),
    CONSTRAINT trusted_devices_seen_after_trusted
        CHECK (last_seen_at >= created_at)
);

ALTER TABLE trusted_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON trusted_devices
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A user's devices in the order they were trusted.
CREATE INDEX trusted_devices_of_user ON trusted_devices (tenant_id, user_id, created_at, id);

-- A forgotten device leaves the session standing on no device, which no
-- posture rule passes.
ALTER TABLE sessions
    ADD CONSTRAINT sessions_signed_in_from_fkey FOREIGN KEY (tenant_id, signed_in_from)
        REFERENCES trusted_devices (tenant_id, id) ON DELETE SET NULL (signed_in_from);

-- The sessions signed in from one device, for its foreign key.
CREATE INDEX sessions_signed_in_from ON sessions (tenant_id, signed_in_from);

-- Where each person signed in from: one row per country, with the place
-- and time of the latest sign-in from it.
CREATE TABLE sign_in_countries (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    country_code text NOT NULL,
    latitude double precision NOT NULL,
    longitude double precision NOT NULL,
    city text,
    signed_in_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id, country_code),
    -- Where a person signed in from describes them and goes with them.
    CONSTRAINT sign_in_countries_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sign_in_countries_on_the_globe
        CHECK (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180)
);

ALTER TABLE sign_in_countries ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign_in_countries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sign_in_countries
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The one-time codes that carry a single sign-on back to the dashboard.
CREATE TABLE sign_in_codes (
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    -- The hash of the secret the dashboard that asked for it holds.
    dashboard_hash text NOT NULL,
    session_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, token_hash),
    -- A code carries one session and opens nothing once it ended.
    CONSTRAINT sign_in_codes_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sign_in_codes_used_in_time
        CHECK (consumed_at IS NULL OR consumed_at < expires_at)
);

ALTER TABLE sign_in_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign_in_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON sign_in_codes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX sign_in_codes_of_session ON sign_in_codes (tenant_id, session_id);

-- The second-factor step of an app sign-in, found by its token's hash.
CREATE TABLE mfa_challenges (
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    session_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    failed_attempts smallint NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, token_hash),
    -- A challenge finishes one session's sign-in and goes with it.
    CONSTRAINT mfa_challenges_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT mfa_challenges_failures_counted
        CHECK (failed_attempts >= 0),
    CONSTRAINT mfa_challenges_answered_in_time
        CHECK (consumed_at IS NULL OR consumed_at < expires_at)
);

ALTER TABLE mfa_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON mfa_challenges
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX mfa_challenges_of_session ON mfa_challenges (tenant_id, session_id);

-- The one-time passes that carry a session to the host of a service
-- accepting it with a cookie of its own. A pass works only in the browser
-- that asked for it: the hash of the value that browser keeps in a cookie
-- of the other host is kept beside the code's.
CREATE TABLE session_handoffs (
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    session_id uuid NOT NULL,
    service_id uuid NOT NULL,
    host text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    browser_hash text NOT NULL,
    PRIMARY KEY (tenant_id, token_hash),
    -- A pass carries one session and opens nothing once it ended.
    CONSTRAINT session_handoffs_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE,
    -- And it is good for one service, so it goes with the service.
    CONSTRAINT session_handoffs_service_fkey FOREIGN KEY (tenant_id, service_id)
        REFERENCES services (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT session_handoffs_used_in_time
        CHECK (consumed_at IS NULL OR consumed_at < expires_at)
);

ALTER TABLE session_handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_handoffs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON session_handoffs
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX session_handoffs_of_session ON session_handoffs (tenant_id, session_id);
CREATE INDEX session_handoffs_of_service ON session_handoffs (tenant_id, service_id);

-- What a tenant's users may give themselves through break glass, one row
-- per tenant that set it. The permissions are both NULL while
-- self-service is off.
CREATE TABLE break_glass_policies (
    tenant_id uuid PRIMARY KEY,
    self_service_system text[],
    self_service_custom text[],
    updated_at timestamptz NOT NULL,
    CONSTRAINT break_glass_policies_self_service_whole
        CHECK (num_nulls(self_service_system, self_service_custom) IN (0, 2)),
    CONSTRAINT break_glass_policies_self_service_grants_something
        CHECK (self_service_system IS NULL
            OR cardinality(self_service_system) + cardinality(self_service_custom) > 0)
);

ALTER TABLE break_glass_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE break_glass_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON break_glass_policies
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
