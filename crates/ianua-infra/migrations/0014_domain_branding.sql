-- The tenant tables of the domain and branding contexts, and the email
-- address changes tenant users asked for: a tenant's registered domains,
-- its look, its own email templates, the mail provider its mail goes out
-- through, and the pending changes of its users' addresses.
--
-- Every table is a tenant table, under row-level security, and lives in a
-- tenant's own database too. That database has no tenants table, so no
-- table here points at one. A hostname belongs to the whole platform, so
-- the claim on it is kept apart, in the platform database
-- (0015_platform_domain_claims.sql), with the certificates that serve it.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- A tenant's registered domains. The row is keyed by tenant and id, not
-- by id alone: a handover saves the registration under the receiving
-- tenant before it is deleted from the giving one, and both may live in
-- the platform database for that moment.
CREATE TABLE registered_domains (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    domain text NOT NULL,
    connection text NOT NULL,
    verification_status text NOT NULL,
    -- When the name was proved, and when the proof was lost, if it was.
    verified_at timestamptz,
    failed_at timestamptz,
    dns_challenge_token text NOT NULL,
    tls_status text NOT NULL,
    created_at timestamptz NOT NULL,
    -- When the verification sweep last asked DNS about it, or NULL before
    -- it first did; the sweep backs off by it.
    last_checked_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT registered_domains_domain_key UNIQUE (tenant_id, domain),
    CONSTRAINT registered_domains_connection_known
        CHECK (connection IN ('self_managed', 'delegated')),
    CONSTRAINT registered_domains_verification_known
        CHECK (verification_status IN ('pending', 'verified', 'failed')),
    CONSTRAINT registered_domains_tls_known
        CHECK (tls_status IN ('not_required', 'provisioning', 'active', 'expired', 'no_certificate')),
    CONSTRAINT registered_domains_proof_fits_status
        CHECK ((verification_status = 'pending' AND verified_at IS NULL AND failed_at IS NULL)
            OR (verification_status = 'verified' AND verified_at IS NOT NULL AND failed_at IS NULL)
            OR (verification_status = 'failed' AND verified_at IS NOT NULL AND failed_at IS NOT NULL)),
    CONSTRAINT registered_domains_verified_after_created
        CHECK (verified_at >= created_at),
    CONSTRAINT registered_domains_lost_after_verified
        CHECK (failed_at >= verified_at),
    CONSTRAINT registered_domains_certificate_only_when_proved
        CHECK (verification_status <> 'pending' OR tls_status <> 'active')
);

ALTER TABLE registered_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE registered_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON registered_domains
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order a list can ask for, the id last to break ties.
CREATE INDEX registered_domains_by_created ON registered_domains (tenant_id, created_at, id);
CREATE INDEX registered_domains_by_domain ON registered_domains (tenant_id, domain, id);
CREATE INDEX registered_domains_by_verification
    ON registered_domains (tenant_id, verification_status, id);
CREATE INDEX registered_domains_by_verified ON registered_domains (tenant_id, verified_at, id);

-- The sweeps across every tenant: the claims still to be proved, oldest
-- first; the proved ones, checked again; and the proved ones still waiting
-- for a certificate, longest waiting first.
CREATE INDEX registered_domains_awaiting_proof ON registered_domains (created_at)
    WHERE verification_status <> 'verified';
CREATE INDEX registered_domains_proved ON registered_domains (tenant_id, id)
    WHERE verification_status = 'verified';
CREATE INDEX registered_domains_awaiting_certificate ON registered_domains (verified_at)
    WHERE verification_status = 'verified' AND tls_status = 'provisioning';

-- A tenant's own look, one row per tenant, each part NULL while it follows
-- the platform's.
CREATE TABLE tenant_branding (
    tenant_id uuid PRIMARY KEY,
    logo_url text,
    primary_color text,
    background_color text,
    -- The CSS the tenant wrote, and the rules kept from it that pages
    -- render: both or neither.
    css_source text,
    css_rendered text,
    email_from_name text,
    email_from_address text,
    CONSTRAINT tenant_branding_css_whole
        CHECK ((css_source IS NULL) = (css_rendered IS NULL))
);

ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_branding
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's own versions of the platform's emails, one per email and
-- locale. The template has no id of its own; the row's id is made when it
-- is first written and kept after, so a list can break ties by it.
CREATE TABLE email_templates (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    template_type text NOT NULL,
    -- The locale it is written for, or NULL for every locale without a
    -- template of its own.
    locale text,
    -- Each part NULL while the platform's is sent.
    subject text,
    body_html text,
    body_text text,
    CONSTRAINT email_templates_slot_key UNIQUE NULLS NOT DISTINCT (tenant_id, template_type, locale),
    CONSTRAINT email_templates_type_known
        CHECK (template_type IN ('Verification', 'PasswordReset', 'MagicLink', 'Invitation',
            'AccountLocked', 'MfaEnrolled', 'RecoveryCodes', 'DeviceTrusted', 'SessionSuspended',
            'BreachedPassword', 'ErasureConfirmation', 'ErasureCompleted', 'Welcome',
            'EmailChangeVerification', 'EmailChanged', 'EmailChangeRequested', 'AccountLinked',
            'SignInCode', 'ExportReady', 'ImpersonationRequested', 'OrgVerification',
            'OrgInvitation', 'OrgWelcome', 'OrgMfaReset', 'OrgEmailChangeRequested',
            'SignupVerification', 'SignupWelcome', 'SignupAccountExists', 'ActivationWelcome',
            'ActivityNotice'))
);

ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON email_templates
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's templates by email, the order a list asks for, the id last.
CREATE INDEX email_templates_by_type ON email_templates (tenant_id, template_type, id);

-- The mail provider a tenant's mail goes out through, one row per tenant.
-- Each kind fills the columns it needs and leaves the others NULL. The
-- credential reaches the store sealed by the crypto adapter and is kept as
-- it came.
CREATE TABLE tenant_mail_providers (
    tenant_id uuid PRIMARY KEY,
    kind text NOT NULL,
    smtp_host text,
    smtp_port integer,
    smtp_security text,
    smtp_username text,
    ses_region text,
    ses_access_key_id text,
    mailgun_domain text,
    mailgun_region text,
    -- The SMTP password, or the API key, secret access key or server token.
    credential text,
    check_state text NOT NULL,
    -- When the last test send went through or failed.
    checked_at timestamptz,
    updated_at timestamptz NOT NULL,
    CONSTRAINT tenant_mail_providers_kind_known
        CHECK (kind IN ('platform', 'smtp', 'sendgrid', 'ses', 'postmark', 'mailgun')),
    CONSTRAINT tenant_mail_providers_check_known
        CHECK (check_state IN ('unverified', 'verified', 'failed')),
    CONSTRAINT tenant_mail_providers_security_known
        CHECK (smtp_security IN ('start_tls', 'implicit_tls')),
    CONSTRAINT tenant_mail_providers_region_known
        CHECK (mailgun_region IN ('us', 'eu')),
    CONSTRAINT tenant_mail_providers_port_in_range
        CHECK (smtp_port BETWEEN 1 AND 65535),
    CONSTRAINT tenant_mail_providers_check_fits_state
        CHECK ((check_state = 'unverified') = (checked_at IS NULL)),
    CONSTRAINT tenant_mail_providers_platform_untested
        CHECK (kind <> 'platform' OR check_state = 'unverified'),
    CONSTRAINT tenant_mail_providers_credential_fits_kind
        CHECK ((kind = 'platform') = (credential IS NULL)),
    CONSTRAINT tenant_mail_providers_smtp_whole
        CHECK ((kind = 'smtp') = (num_nonnulls(smtp_host, smtp_port, smtp_security, smtp_username) = 4)
            AND num_nonnulls(smtp_host, smtp_port, smtp_security, smtp_username) IN (0, 4)),
    CONSTRAINT tenant_mail_providers_ses_whole
        CHECK ((kind = 'ses') = (num_nonnulls(ses_region, ses_access_key_id) = 2)
            AND num_nonnulls(ses_region, ses_access_key_id) IN (0, 2)),
    CONSTRAINT tenant_mail_providers_mailgun_whole
        CHECK ((kind = 'mailgun') = (num_nonnulls(mailgun_domain, mailgun_region) = 2)
            AND num_nonnulls(mailgun_domain, mailgun_region) IN (0, 2)),
    CONSTRAINT tenant_mail_providers_tested_after_named
        CHECK (checked_at >= updated_at)
);

ALTER TABLE tenant_mail_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_mail_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON tenant_mail_providers
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The address changes tenant users asked for, at most one per user. Only
-- the hashes of the mailed links are kept.
CREATE TABLE email_changes (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    from_email text NOT NULL,
    new_email text NOT NULL,
    token_hash text NOT NULL,
    cancel_token_hash text NOT NULL,
    state text NOT NULL,
    -- When it was confirmed or cancelled, or NULL while it waits.
    settled_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT email_changes_token_key UNIQUE (tenant_id, token_hash),
    CONSTRAINT email_changes_cancel_token_key UNIQUE (tenant_id, cancel_token_hash),
    -- A change is the account's own and means nothing once it is gone.
    CONSTRAINT email_changes_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT email_changes_state_known
        CHECK (state IN ('waiting', 'confirmed', 'cancelled')),
    CONSTRAINT email_changes_settled_fits_state
        CHECK ((state = 'waiting') = (settled_at IS NULL)),
    CONSTRAINT email_changes_to_another_address
        CHECK (new_email <> from_email),
    CONSTRAINT email_changes_expires_after_asked
        CHECK (expires_at > created_at),
    CONSTRAINT email_changes_settled_after_asked
        CHECK (settled_at >= created_at),
    CONSTRAINT email_changes_confirmed_in_time
        CHECK (state <> 'confirmed' OR settled_at < expires_at)
);

ALTER TABLE email_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON email_changes
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
