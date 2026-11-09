-- The organization's members and everything kept about them: their
-- accounts, sign-in, credentials, sessions, invitations, privacy records,
-- the organization's own identity provider, branding, subscription and API
-- keys, and the sign-ups still waiting to become organizations.
--
-- Platform tables, in the platform database only. A table that carries a
-- tenant's id is under row-level security like every tenant table. A row
-- that names a member names the member's organization with it, so a member
-- of one organization can never be attached to another's records.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- Organization members: one person's account in one organization.
CREATE TABLE org_users (
    id uuid PRIMARY KEY,
    -- A member cannot exist without their organization, so it goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email text NOT NULL,
    display_name text NOT NULL,
    -- The password hash, or NULL while none is set.
    password_hash text,
    status text NOT NULL,
    role text NOT NULL,
    email_standing text NOT NULL,
    -- The member's own locale and timezone, or NULL to follow the
    -- organization's.
    locale text,
    timezone text,
    joined_at timestamptz,
    credentials_changed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Whether the installation's setup token or an accepted invitation
    -- still vouches for the next sign-in: set by either, cleared by the
    -- first sign-in after it.
    route_vouches boolean NOT NULL DEFAULT false,
    CONSTRAINT org_users_email_key UNIQUE (organization_id, email),
    CONSTRAINT org_users_organization_id_key UNIQUE (organization_id, id),
    CONSTRAINT org_users_status_known
        CHECK (status IN ('invited', 'pending_verification', 'active', 'locked', 'deactivated', 'closing')),
    CONSTRAINT org_users_role_known
        CHECK (role IN ('viewer', 'billing', 'member', 'admin', 'owner')),
    CONSTRAINT org_users_email_standing_known
        CHECK (email_standing IN ('unverified', 'verified')),
    CONSTRAINT org_users_joining_fits_status
        CHECK ((status <> 'pending_verification' OR joined_at IS NULL)
            AND (status NOT IN ('active', 'locked', 'closing') OR joined_at IS NOT NULL)),
    CONSTRAINT org_users_changed_after_created
        CHECK (updated_at >= created_at),
    CONSTRAINT org_users_joined_after_created
        CHECK (joined_at >= created_at),
    CONSTRAINT org_users_credentials_changed_after_created
        CHECK (credentials_changed_at >= created_at),
    -- Only a member who joined holds a vouch.
    CONSTRAINT org_users_route_vouches_once_joined
        CHECK (NOT route_vouches OR joined_at IS NOT NULL)
);

-- One index per order a member list can ask for, within one organization,
-- the id last to break ties, and the same led by status for a list
-- narrowed to one status.
CREATE INDEX org_users_by_created ON org_users (organization_id, created_at, id);
CREATE INDEX org_users_by_updated ON org_users (organization_id, updated_at, id);
CREATE INDEX org_users_by_email ON org_users (organization_id, email, id);
CREATE INDEX org_users_by_display_name ON org_users (organization_id, display_name, id);
CREATE INDEX org_users_by_status ON org_users (organization_id, status, id);
CREATE INDEX org_users_by_status_created ON org_users (organization_id, status, created_at, id);

-- Every organization's account on one address, for sign-in pages that
-- carry no organization.
CREATE INDEX org_users_by_address ON org_users (email);

-- An organization's owners, read before a change that could leave it
-- without one; and the members whose role reaches every tenant.
CREATE INDEX org_users_by_role ON org_users (organization_id, role);

-- A grant cannot outlive the member who holds it.
ALTER TABLE org_tenant_grants
    ADD CONSTRAINT org_tenant_grants_org_user_id_fkey
    FOREIGN KEY (org_user_id) REFERENCES org_users (id) ON DELETE CASCADE;

-- The member who suspended an organization is part of the suspension's
-- record, so that member cannot be removed while the record stands: the
-- suspension is lifted first.
ALTER TABLE organizations
    ADD CONSTRAINT organizations_suspended_by_member_fkey
    FOREIGN KEY (id, suspended_by_member) REFERENCES org_users (organization_id, id)
    ON DELETE RESTRICT;

CREATE INDEX organizations_suspended_by ON organizations (id, suspended_by_member);

-- One person's accounts across an organization's tenants, grouped under
-- their shared address. The group is the organization's; its links each
-- name a tenant, in their own table under row-level security.
CREATE TABLE org_linked_identities (
    id uuid PRIMARY KEY,
    -- A group cannot exist without its organization, so it goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT org_linked_identities_email_key UNIQUE (organization_id, email)
);

-- One link of a group: the account the person holds in one tenant. Every
-- link carries the group's address, so it is not repeated here.
CREATE TABLE org_linked_identity_links (
    -- A link means nothing without its group, so it goes with it.
    linked_identity_id uuid NOT NULL REFERENCES org_linked_identities (id) ON DELETE CASCADE,
    -- A link to a removed tenant points nowhere, so it goes with the tenant.
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- no foreign key: the account lives in the tenant's own database, which may not be this one.
    user_id uuid NOT NULL,
    linked_at timestamptz NOT NULL,
    PRIMARY KEY (linked_identity_id, tenant_id),
    -- A tenant account belongs to one group at most. It also leads with the
    -- tenant, so removing a tenant finds its links by it.
    CONSTRAINT org_linked_identity_links_account_key UNIQUE (tenant_id, user_id)
);

ALTER TABLE org_linked_identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_linked_identity_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON org_linked_identity_links
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Invitations to join an organization, each for one member's account.
CREATE TABLE org_invitations (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    -- An invitation is for one account and means nothing without it, so it
    -- goes when the account is removed.
    org_user_id uuid NOT NULL,
    email text NOT NULL,
    -- The member who sent it.
    -- no foreign key: the invitation stays on record when its sender is removed later, and removing them must not wait on the invitations they once sent.
    invited_by uuid NOT NULL,
    token_hash text NOT NULL,
    status text NOT NULL,
    accepted_at timestamptz,
    message text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT org_invitations_org_user_id_fkey
        FOREIGN KEY (organization_id, org_user_id) REFERENCES org_users (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT org_invitations_token_hash_key UNIQUE (token_hash),
    CONSTRAINT org_invitations_status_known
        CHECK (status IN ('pending', 'accepted', 'declined', 'expired', 'revoked')),
    CONSTRAINT org_invitations_acceptance_fits_status
        CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    CONSTRAINT org_invitations_accepted_after_sent
        CHECK (accepted_at >= created_at),
    CONSTRAINT org_invitations_accepted_in_time
        CHECK (accepted_at < expires_at)
);

-- An account's invitations, by status: the pending one of a member, and
-- the foreign key to the account.
CREATE INDEX org_invitations_of_member ON org_invitations (organization_id, org_user_id, status);

-- An organization's pending invitations, oldest first, and the one sent to
-- an address.
CREATE INDEX org_invitations_pending ON org_invitations (organization_id, created_at, id)
    WHERE status = 'pending';
CREATE INDEX org_invitations_pending_to ON org_invitations (organization_id, email, created_at, id)
    WHERE status = 'pending';

-- The pending invitations whose link ran out, for the sweep that marks
-- them expired.
CREATE INDEX org_invitations_lapsing ON org_invitations (expires_at, id)
    WHERE status = 'pending';

-- Sign-ups waiting for their founder to follow the mailed link. They
-- belong to no organization yet, and are found by the hash of the link's
-- token alone.
CREATE TABLE pending_signups (
    token_hash text PRIMARY KEY,
    email text NOT NULL,
    company_name text NOT NULL,
    tenant_name text NOT NULL,
    admin_display_name text NOT NULL,
    password_hash text NOT NULL,
    timezone text NOT NULL,
    locale text NOT NULL,
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT pending_signups_link_ends_after_asked
        CHECK (expires_at > requested_at),
    CONSTRAINT pending_signups_link_works_a_day_at_most
        CHECK (expires_at <= requested_at + interval '1 day')
);

-- An organization's own branding, one row per organization, each part
-- NULL while it follows the platform's.
CREATE TABLE org_branding (
    -- Branding means nothing without its organization, so it goes with it.
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    logo_url text,
    primary_color text,
    sender_name text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT org_branding_changed_after_made
        CHECK (updated_at >= created_at)
);

-- Organization API keys. Only the hash of a key is kept, beside the
-- prefix that lets a leaked key be recognised. A revoked key stays on
-- record so its past use can be audited.
CREATE TABLE org_api_keys (
    id uuid PRIMARY KEY,
    -- A key works only for its organization, so it goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    scopes text[] NOT NULL,
    -- The member who made it.
    -- no foreign key: the key stays on record, revoked by the platform, when its creator is removed, for the audit of its past use.
    created_by uuid NOT NULL,
    -- The key it was minted through, or NULL when minted through its
    -- creator's session. A key minted through a key lives no longer than
    -- it, so it goes when that key is removed.
    parent_key_id uuid,
    -- When it stops working, or NULL when it never does.
    expires_at timestamptz,
    last_used_at timestamptz,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT org_api_keys_organization_id_key UNIQUE (organization_id, id),
    CONSTRAINT org_api_keys_key_hash_key UNIQUE (key_hash),
    CONSTRAINT org_api_keys_parent_key_id_fkey
        FOREIGN KEY (organization_id, parent_key_id) REFERENCES org_api_keys (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT org_api_keys_status_known
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT org_api_keys_grants_something
        CHECK (cardinality(scopes) > 0),
    CONSTRAINT org_api_keys_not_minted_through_itself
        CHECK (parent_key_id <> id),
    CONSTRAINT org_api_keys_used_after_created
        CHECK (last_used_at >= created_at),
    CONSTRAINT org_api_keys_expires_after_created
        CHECK (expires_at > created_at)
);

-- One index per order an organization's key list can ask for, the id last
-- to break ties.
CREATE INDEX org_api_keys_by_created ON org_api_keys (organization_id, created_at, id);
CREATE INDEX org_api_keys_by_name ON org_api_keys (organization_id, name, id);
CREATE INDEX org_api_keys_by_last_used ON org_api_keys (organization_id, last_used_at, id);
CREATE INDEX org_api_keys_by_expiry ON org_api_keys (organization_id, expires_at, id);

-- The keys minted through a key, walked down the tree when it is revoked,
-- and the foreign key to that key.
CREATE INDEX org_api_keys_minted_through ON org_api_keys (organization_id, parent_key_id);

-- A session's tenant must be one of the session's organization, so the
-- tenant is named with the organization it belongs to.
ALTER TABLE tenants
    ADD CONSTRAINT tenants_organization_id_key UNIQUE (organization_id, id);

-- Members' sessions on the management plane.
--
-- A session works in one tenant or on the organization alone. The tenant
-- is kept in `working_tenant`, not in a `tenant_id`: a session belongs to
-- its organization, and row-level security asking for a tenant would hide
-- every session that works on the organization alone.
CREATE TABLE org_sessions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    org_user_id uuid NOT NULL,
    -- The tenant it manages, or NULL when it works on the organization
    -- alone.
    working_tenant uuid,
    refresh_token_hash text NOT NULL,
    auth_method text NOT NULL,
    -- The strongest second factor proved, or NULL for none yet.
    factor text,
    owed text NOT NULL,
    -- What the client sent, or NULL when nobody observed it.
    ip_address text,
    user_agent text,
    status text NOT NULL,
    -- The change of how the member signs in the session was kept through,
    -- or NULL for none.
    kept_through timestamptz,
    created_at timestamptz NOT NULL,
    last_active_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT org_sessions_refresh_token_hash_key UNIQUE (refresh_token_hash),
    -- A session cannot outlive the member signed in to it.
    CONSTRAINT org_sessions_member_fkey
        FOREIGN KEY (organization_id, org_user_id)
        REFERENCES org_users (organization_id, id) ON DELETE CASCADE,
    -- A session in a tenant that is gone has nothing left to manage.
    CONSTRAINT org_sessions_working_tenant_fkey
        FOREIGN KEY (organization_id, working_tenant)
        REFERENCES tenants (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT org_sessions_auth_method_known
        CHECK (auth_method IN ('password', 'magic_link', 'passkey', 'saml', 'oidc')),
    CONSTRAINT org_sessions_factor_known
        CHECK (factor IN ('totp', 'email_code', 'sms_code', 'recovery_code', 'hardware_key',
                          'passkey', 'email_confirmation', 'provider_multi_factor',
                          'provider_hardware_key')),
    CONSTRAINT org_sessions_owed_known
        CHECK (owed IN ('not_owed', 'verify', 'enrol', 'confirm_by_email', 'confirm_then_enrol')),
    CONSTRAINT org_sessions_status_known
        CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT org_sessions_used_after_created
        CHECK (last_active_at >= created_at),
    CONSTRAINT org_sessions_expires_after_created
        CHECK (expires_at >= created_at)
);

-- One index per order a list of an organization's sessions can ask for,
-- the id last to break ties.
CREATE INDEX org_sessions_by_created ON org_sessions (organization_id, created_at, id);
CREATE INDEX org_sessions_by_last_active ON org_sessions (organization_id, last_active_at, id);
CREATE INDEX org_sessions_by_expiry ON org_sessions (organization_id, expires_at, id);

-- The member a session belongs to, for the foreign key.
CREATE INDEX org_sessions_of_member_in_organization ON org_sessions (organization_id, org_user_id);

-- A member's own sessions, newest first, and revoking them all.
CREATE INDEX org_sessions_of_member ON org_sessions (org_user_id, created_at, id);

-- The tenant a session works in, for the foreign key.
CREATE INDEX org_sessions_in_tenant ON org_sessions (organization_id, working_tenant);

-- The sessions long past their expiry, for the sweep that deletes them.
CREATE INDEX org_sessions_expired ON org_sessions (expires_at);

-- The devices members trust to skip their second factor.
--
-- A device is the person's own, so it is kept by member alone: no admin of
-- the organization reads or revokes it.
CREATE TABLE org_trusted_devices (
    id uuid PRIMARY KEY,
    -- A device is trusted by the member who remembered it, and goes with
    -- them.
    org_user_id uuid NOT NULL REFERENCES org_users (id) ON DELETE CASCADE,
    secret_hash text NOT NULL,
    device_name text NOT NULL,
    last_user_agent text NOT NULL,
    last_ip text NOT NULL,
    status text NOT NULL,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT org_trusted_devices_status_known
        CHECK (status IN ('trusted', 'revoked')),
    CONSTRAINT org_trusted_devices_seen_after_trusted
        CHECK (last_seen_at >= created_at)
);

-- A member's devices, in the order they were trusted.
CREATE INDEX org_trusted_devices_of_member ON org_trusted_devices (org_user_id, created_at, id);

-- A member's second factor: at most one enrollment each, of one kind.
CREATE TABLE org_mfa_enrollments (
    -- The member is the enrollment's key. A factor is part of the member's
    -- account and goes with it.
    org_user_id uuid PRIMARY KEY REFERENCES org_users (id) ON DELETE CASCADE,
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
    -- The latest TOTP step accepted, so a code is never accepted twice.
    last_claimed_step bigint,
    enrolled_at timestamptz NOT NULL,
    CONSTRAINT org_mfa_enrollments_method_known
        CHECK (method IN ('totp', 'email_code', 'sms_code')),
    CONSTRAINT org_mfa_enrollments_status_known
        CHECK (status IN ('pending', 'verified', 'disabled')),
    CONSTRAINT org_mfa_enrollments_secret_fits_method
        CHECK ((method = 'totp') = (sealed_secret IS NOT NULL)),
    CONSTRAINT org_mfa_enrollments_phone_fits_method
        CHECK ((method = 'sms_code') = (phone_number IS NOT NULL)),
    CONSTRAINT org_mfa_enrollments_confirmation_whole
        CHECK ((verified_at IS NULL) = (recovery_codes_hash IS NULL)),
    CONSTRAINT org_mfa_enrollments_times_fit_status
        CHECK ((status = 'pending' AND verified_at IS NULL AND disabled_at IS NULL)
            OR (status = 'verified' AND verified_at IS NOT NULL AND disabled_at IS NULL)
            OR (status = 'disabled' AND disabled_at IS NOT NULL)),
    CONSTRAINT org_mfa_enrollments_failures_whole
        CHECK (failed_attempts >= 0 AND (failed_attempts = 0) = (last_failed_at IS NULL)),
    CONSTRAINT org_mfa_enrollments_confirmed_after_enrolled
        CHECK (verified_at >= enrolled_at),
    CONSTRAINT org_mfa_enrollments_disabled_after_enrolled
        CHECK (disabled_at >= enrolled_at),
    CONSTRAINT org_mfa_enrollments_disabled_after_confirmed
        CHECK (disabled_at >= verified_at),
    CONSTRAINT org_mfa_enrollments_step_known
        CHECK (last_claimed_step >= 0)
);

-- A member's passkeys. A credential id is unique on the whole platform:
-- the login plane is flat, so the credential is what names its member.
CREATE TABLE org_passkey_credentials (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    org_user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL,
    authenticator_type text NOT NULL,
    attestation text NOT NULL,
    name text NOT NULL,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL,
    -- A passkey is part of the member's account and goes with it; the pair
    -- keeps it to the member's own organization.
    FOREIGN KEY (organization_id, org_user_id) REFERENCES org_users (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT org_passkey_credentials_credential_key UNIQUE (credential_id),
    CONSTRAINT org_passkey_credentials_authenticator_known
        CHECK (authenticator_type IN ('platform', 'cross_platform')),
    CONSTRAINT org_passkey_credentials_attestation_known
        CHECK (attestation IN ('unattested', 'hardware_key')),
    CONSTRAINT org_passkey_credentials_sign_count_fits
        CHECK (sign_count BETWEEN 0 AND 4294967295 AND (sign_count = 0 OR last_used_at IS NOT NULL)),
    CONSTRAINT org_passkey_credentials_used_after_created
        CHECK (last_used_at >= created_at)
);

-- The member a passkey belongs to, for the foreign key; and a member's
-- passkeys in the order they were added.
CREATE INDEX org_passkey_credentials_of_member ON org_passkey_credentials (organization_id, org_user_id);
CREATE INDEX org_passkey_credentials_by_member ON org_passkey_credentials (org_user_id, created_at, id);

-- Passkey ceremonies in flight on the management plane, by their id
-- alone: one opened for a discoverable sign-in names nobody yet.
CREATE TABLE org_passkey_ceremonies (
    id uuid PRIMARY KEY,
    -- The member the ceremony was opened for, or NULL for a discoverable
    -- sign-in. A ceremony means nothing without its member.
    org_user_id uuid REFERENCES org_users (id) ON DELETE CASCADE,
    purpose text NOT NULL,
    -- The verifier's opaque state between the challenge and the answer.
    state bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT org_passkey_ceremonies_purpose_known
        CHECK (purpose IN ('registration', 'authentication', 'discoverable_authentication')),
    CONSTRAINT org_passkey_ceremonies_subject_fits_purpose
        CHECK ((org_user_id IS NULL) = (purpose = 'discoverable_authentication')),
    CONSTRAINT org_passkey_ceremonies_expires_after_created
        CHECK (expires_at >= created_at),
    CONSTRAINT org_passkey_ceremonies_settled_in_time
        CHECK (consumed_at >= created_at AND consumed_at < expires_at)
);

-- The member a ceremony was opened for, for the foreign key.
CREATE INDEX org_passkey_ceremonies_of_member ON org_passkey_ceremonies (org_user_id);

-- A member's set of recovery codes: when it was made, one row per set.
CREATE TABLE org_recovery_code_sets (
    -- The set is part of the member's account and goes with it.
    org_user_id uuid PRIMARY KEY REFERENCES org_users (id) ON DELETE CASCADE,
    generated_at timestamptz NOT NULL
);

-- The codes of a set, each its own row, so spending one is one update
-- that only one sign-in can win.
CREATE TABLE org_recovery_codes (
    -- A code belongs to its set and goes with it.
    org_user_id uuid NOT NULL REFERENCES org_recovery_code_sets (org_user_id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (org_user_id, code_hash)
);

-- Single-use links mailed to members, every purpose in one table, each
-- read under its own purpose only.
CREATE TABLE org_tokens (
    token_hash text PRIMARY KEY,
    purpose text NOT NULL,
    -- A link is issued to one member and goes with them.
    org_user_id uuid NOT NULL REFERENCES org_users (id) ON DELETE CASCADE,
    sent_to text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT org_tokens_purpose_known
        CHECK (purpose IN ('email_verification', 'password_reset', 'magic_link', 'sign_in_confirmation', 'installation_setup')),
    CONSTRAINT org_tokens_expires_after_created
        CHECK (expires_at >= created_at),
    CONSTRAINT org_tokens_used_in_time
        CHECK (consumed_at >= created_at AND consumed_at < expires_at)
);

-- A member's links of one purpose, newest last: for the latest one sent,
-- and for spending every one still outstanding.
CREATE INDEX org_tokens_of_member ON org_tokens (org_user_id, purpose, created_at, token_hash);

-- The organization's own identity provider, at most one per organization,
-- over SAML or OIDC. Its settings are kept whole in the column of its
-- protocol, the other left empty.
CREATE TABLE org_identity_providers (
    id uuid PRIMARY KEY,
    -- A provider signs members in for its organization alone, so it goes
    -- with the organization.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name text NOT NULL,
    saml jsonb,
    -- The OIDC settings, the client secret in them sealed by the platform.
    oidc jsonb,
    email_trust text NOT NULL,
    assurance_trust text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT org_identity_providers_organization_key UNIQUE (organization_id),
    CONSTRAINT org_identity_providers_organization_id_key UNIQUE (organization_id, id),
    CONSTRAINT org_identity_providers_one_protocol
        CHECK (num_nonnulls(saml, oidc) = 1),
    CONSTRAINT org_identity_providers_email_trust_known
        CHECK (email_trust IN ('unverified', 'authoritative')),
    CONSTRAINT org_identity_providers_assurance_trust_known
        CHECK (assurance_trust IN ('untrusted', 'trusted')),
    CONSTRAINT org_identity_providers_status_known
        CHECK (status IN ('active', 'disabled'))
);

-- The dashboard sign-ins sent to the organization's provider and waiting
-- on its answer. Each is kept under a digest of its key, never the key
-- itself: the OIDC state is a secret the browser holds, and a reader of
-- this table cannot answer a sign-in with it. The kind of key keeps an
-- OIDC state and a SAML request id apart even when their text is the same.
CREATE TABLE org_sso_requests (
    key_kind text NOT NULL,
    key_hash bytea NOT NULL,
    organization_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    binding_hash text NOT NULL,
    tenant_slug text,
    -- What an OIDC answer is checked with; all empty for SAML. The PKCE
    -- verifier is kept only until the answer comes back, minutes at most,
    -- and is worth nothing without the code the provider sends the
    -- browser.
    nonce text,
    pkce_verifier text,
    redirect_uri text,
    lapses_at timestamptz NOT NULL,
    PRIMARY KEY (key_kind, key_hash),
    -- A sign-in waiting on a provider that was removed can never finish,
    -- so it goes with the provider, and with its organization.
    CONSTRAINT org_sso_requests_connection_fkey
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES org_identity_providers (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT org_sso_requests_key_kind_known
        CHECK (key_kind IN ('oidc_state', 'saml_request')),
    CONSTRAINT org_sso_requests_oidc_whole
        CHECK (num_nonnulls(nonce, pkce_verifier, redirect_uri) IN (0, 3))
);

CREATE INDEX org_sso_requests_of_connection ON org_sso_requests (organization_id, connection_id);

-- The requests whose time ran out, cleared as new ones are kept.
CREATE INDEX org_sso_requests_lapsing ON org_sso_requests (lapses_at);

-- The SAML assertions the organizations' providers sent that were spent,
-- each kept until it would have expired anyway.
CREATE TABLE org_saml_assertions (
    assertion_id text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

-- The assertions past their expiry, cleared as new ones are spent.
CREATE INDEX org_saml_assertions_expiring ON org_saml_assertions (expires_at);

-- A member's requests to be erased.
CREATE TABLE org_erasure_requests (
    id uuid PRIMARY KEY,
    -- A request is the organization's record and goes with it.
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- no foreign key: the request outlives the member it erases, as the record that the erasure was carried out.
    org_user_id uuid NOT NULL,
    reason text,
    status text NOT NULL,
    completed_at timestamptz,
    requested_at timestamptz NOT NULL,
    scheduled_at timestamptz NOT NULL,
    cancel_token_hash text NOT NULL,
    sent_to text NOT NULL,
    CONSTRAINT org_erasure_requests_cancel_token_key UNIQUE (cancel_token_hash),
    CONSTRAINT org_erasure_requests_status_known
        CHECK (status IN ('pending', 'processing', 'completed', 'cancelled', 'held', 'failed')),
    CONSTRAINT org_erasure_requests_completion_fits_status
        CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CONSTRAINT org_erasure_requests_grace_in_bounds
        CHECK (scheduled_at >= requested_at + interval '24 hours'
            AND scheduled_at <= requested_at + interval '720 hours'),
    CONSTRAINT org_erasure_requests_completed_after_grace
        CHECK (completed_at >= scheduled_at)
);

-- At most one request per member still under way, which is also how the
-- one under way is found.
CREATE UNIQUE INDEX org_erasure_requests_one_under_way ON org_erasure_requests (organization_id, org_user_id)
    WHERE status NOT IN ('completed', 'cancelled');

-- Every request of an organization, finished ones included: for the link to
-- the organization, which the partial index above cannot serve.
CREATE INDEX org_erasure_requests_of_organization ON org_erasure_requests (organization_id, org_user_id);

-- The requests the sweep carries out: pending ones by when they fall due,
-- and failed ones due a retry.
CREATE INDEX org_erasure_requests_due ON org_erasure_requests (scheduled_at, id)
    WHERE status IN ('pending', 'failed');

-- Every consent decision a member made. Records are only ever added.
CREATE TABLE org_consents (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    org_user_id uuid NOT NULL,
    consent_type text NOT NULL,
    granted boolean NOT NULL,
    version text NOT NULL,
    ip_address text,
    recorded_at timestamptz NOT NULL,
    -- A member's consents are their personal data, so they go with the
    -- member when the member is erased.
    CONSTRAINT org_consents_org_user_fkey
        FOREIGN KEY (organization_id, org_user_id)
        REFERENCES org_users (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT org_consents_consent_type_known
        CHECK (consent_type IN ('data_processing', 'marketing', 'terms_of_service',
            'privacy_policy', 'health_data_sharing', 'cookies'))
);

-- A member's decisions newest first, and their latest on one kind.
CREATE INDEX org_consents_of_member ON org_consents (organization_id, org_user_id, recorded_at, id);
CREATE INDEX org_consents_of_member_by_type
    ON org_consents (organization_id, org_user_id, consent_type, recorded_at, id);

-- Subscriptions: what each organization pays for, one per organization.
CREATE TABLE org_subscriptions (
    -- A subscription is the organization's own and means nothing without
    -- it, so it goes with the organization.
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    plan text NOT NULL,
    cycle text NOT NULL,
    state text NOT NULL,
    -- When a running trial ends, set only while trialing.
    trial_ends_at timestamptz,
    -- Since when a payment is owed, set only while past due.
    past_due_since timestamptz,
    -- The payment provider's reference to the method on file, or NULL when
    -- none was ever added. Never a card number.
    payment_reference text,
    trial text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT org_subscriptions_plan_known
        CHECK (plan IN ('free', 'starter', 'business', 'custom', 'self_hosted')),
    CONSTRAINT org_subscriptions_cycle_known
        CHECK (cycle IN ('monthly', 'annual')),
    CONSTRAINT org_subscriptions_state_known
        CHECK (state IN ('trialing', 'active', 'past_due')),
    CONSTRAINT org_subscriptions_trial_known
        CHECK (trial IN ('unused', 'used')),
    CONSTRAINT org_subscriptions_times_fit_state
        CHECK ((state = 'trialing') = (trial_ends_at IS NOT NULL)
            AND (state = 'past_due') = (past_due_since IS NOT NULL)),
    CONSTRAINT org_subscriptions_trial_used_while_trialing
        CHECK (state <> 'trialing' OR trial = 'used'),
    CONSTRAINT org_subscriptions_changed_after_created
        CHECK (updated_at >= created_at)
);

-- The trials still running, by when they end, for the sweep that ends
-- them.
CREATE INDEX org_subscriptions_trialing ON org_subscriptions (trial_ends_at, organization_id)
    WHERE state = 'trialing';

-- The subscriptions a payment is owed on, by when it fell due, for the
-- sweep that suspends the ones overdue too long.
CREATE INDEX org_subscriptions_past_due ON org_subscriptions (past_due_since, organization_id)
    WHERE state = 'past_due';
