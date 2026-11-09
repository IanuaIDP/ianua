-- The agents context, who an agent is and what it may reach: the agents,
-- the keys they sign in with, the challenges of their attestations, the
-- delegations they act under and the delegations they ask people for,
-- the task templates people approve, the grants on named resources, the
-- agents seen at work that nobody registered, and the most sensitive data
-- each agent has touched.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- Only what the domain hands over is kept: an agent's public keys, never
-- a private one, which the platform never holds.

-- An agent, with the person who owns it. A person is kept as the kind of
-- the account they act through, the account, and the person behind it.
CREATE TABLE agents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    owner_kind text NOT NULL,
    -- no foreign key: the owner is a tenant user or an organization member, by owner_kind, and an organization member lives in the platform database.
    owner_id uuid NOT NULL,
    owner_person text NOT NULL,
    -- The person the agent was offered to, open or lapsed, or NULL when
    -- nobody was.
    offered_to_kind text,
    -- no foreign key: the person offered the agent is a tenant user or an organization member, by offered_to_kind, and an organization member lives in the platform database.
    offered_to_id uuid,
    offered_to_person text,
    offered_at timestamptz,
    offer_expires_at timestamptz,
    status text NOT NULL,
    -- The policy the agent attests under, or NULL for one that proves
    -- itself with a key enrolled by hand.
    attestation_policy jsonb,
    -- When someone required the agent to re-attest, or NULL while it is
    -- free to act.
    reattestation_required_since timestamptz,
    last_attested_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT agents_tenant_id_key UNIQUE (tenant_id, id),
    -- People pick an agent by its name in the dashboard and the audit
    -- trail, and two agents of one name cannot be told apart there.
    CONSTRAINT agents_name_key UNIQUE (tenant_id, name),
    CONSTRAINT agents_status_known CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT agents_owner_kind_known CHECK (owner_kind IN ('user', 'org_user')),
    CONSTRAINT agents_offered_to_kind_known CHECK (offered_to_kind IN ('user', 'org_user')),
    CONSTRAINT agents_offer_whole CHECK (
        num_nonnulls(offered_to_kind, offered_to_id, offered_to_person, offered_at,
                     offer_expires_at) IN (0, 5)
    ),
    CONSTRAINT agents_offer_lapses_after_made CHECK (offer_expires_at > offered_at),
    CONSTRAINT agents_offered_after_created CHECK (offered_at >= created_at),
    CONSTRAINT agents_attested_after_created CHECK (last_attested_at >= created_at),
    CONSTRAINT agents_held_after_created CHECK (reattestation_required_since >= created_at),
    CONSTRAINT agents_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agents
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- One index per order an agent list can ask for, the id last; the status
-- one also finds every active agent of a tenant for a tenant-wide stop.
CREATE INDEX agents_by_created ON agents (tenant_id, created_at, id);
CREATE INDEX agents_by_updated ON agents (tenant_id, updated_at, id);
CREATE INDEX agents_by_name ON agents (tenant_id, name, id);
CREATE INDEX agents_by_status ON agents (tenant_id, status, id);
-- The agents a tenant-wide stop suspended, read back by when it stamped them.
CREATE INDEX agents_suspended_by_change ON agents (tenant_id, updated_at, id)
    WHERE status = 'suspended';
CREATE INDEX agents_owned_by ON agents (tenant_id, owner_kind, owner_id, created_at, id);
CREATE INDEX agents_offered_to ON agents (tenant_id, offered_to_kind, offered_to_id, created_at, id)
    WHERE offered_to_id IS NOT NULL;

-- The public keys an agent signs its assertions with, active and rotated.
CREATE TABLE agent_credentials (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    kid text NOT NULL,
    algorithm text NOT NULL,
    public_key text NOT NULL,
    status text NOT NULL,
    -- When rotation retired it, kept after a revoke too, or NULL when it
    -- was never rotated.
    rotated_at timestamptz,
    -- The attestation it was issued against, or NULL for a key enrolled by
    -- hand.
    attested_method text,
    attested_subject text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT agent_credentials_tenant_id_key UNIQUE (tenant_id, id),
    -- A key speaks for its agent alone, and goes with it.
    CONSTRAINT agent_credentials_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_credentials_algorithm_known CHECK (algorithm IN ('RS256', 'ES256', 'EdDSA')),
    CONSTRAINT agent_credentials_status_known CHECK (status IN ('active', 'rotated', 'revoked')),
    CONSTRAINT agent_credentials_rotation_fits_status CHECK (
        (status = 'active' AND rotated_at IS NULL)
        OR (status = 'rotated' AND rotated_at IS NOT NULL)
        OR status = 'revoked'
    ),
    CONSTRAINT agent_credentials_attestation_whole
        CHECK (num_nonnulls(attested_method, attested_subject) IN (0, 2)),
    CONSTRAINT agent_credentials_attested_method_known CHECK (
        attested_method IN ('spiffe', 'aws_iam', 'gcp_instance_identity', 'tpm',
                            'kubernetes_service_account', 'github_actions', 'oidc_token',
                            'azure_managed_identity')
    ),
    CONSTRAINT agent_credentials_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT agent_credentials_rotated_after_created CHECK (rotated_at >= created_at),
    CONSTRAINT agent_credentials_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_credentials
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX agent_credentials_of_agent
    ON agent_credentials (tenant_id, agent_id, created_at, id);
-- The credentials one workload identity was attested as, so it never
-- bootstraps a second agent.
CREATE INDEX agent_credentials_by_subject ON agent_credentials (tenant_id, attested_subject)
    WHERE attested_subject IS NOT NULL;

-- The one agent each workload identity bootstrapped. The credentials keep
-- the subject too, one row per key, so they cannot hold it unique; this
-- holds it once per tenant, so two agents bootstrapped for one workload at
-- the same moment cannot both be kept: the second is refused.
CREATE TABLE agent_workloads (
    tenant_id uuid NOT NULL,
    attested_subject text NOT NULL,
    agent_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, attested_subject),
    -- A workload is bound to its agent alone, and is free again once the
    -- agent is deleted.
    CONSTRAINT agent_workloads_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE agent_workloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_workloads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_workloads
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The workload an agent is bound to, and the foreign key.
CREATE INDEX agent_workloads_of_agent ON agent_workloads (tenant_id, agent_id);

-- The single-use nonces an agent signs to prove where it runs. Spending
-- one is one statement, so no nonce is spent twice.
CREATE TABLE agent_attestation_challenges (
    tenant_id uuid NOT NULL,
    nonce text NOT NULL,
    agent_id uuid NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- When it was spent, or NULL while it is not.
    used_at timestamptz,
    PRIMARY KEY (tenant_id, nonce),
    -- A challenge bootstraps its agent alone, and goes with it.
    CONSTRAINT agent_attestation_challenges_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_attestation_challenges_expires_after_issued
        CHECK (expires_at > issued_at),
    CONSTRAINT agent_attestation_challenges_spent_while_valid
        CHECK (used_at IS NULL OR (used_at >= issued_at AND used_at < expires_at))
);

ALTER TABLE agent_attestation_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_attestation_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_attestation_challenges
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX agent_attestation_challenges_of_agent
    ON agent_attestation_challenges (tenant_id, agent_id);

-- Authority one principal hands to one agent. What it grants and its
-- limits are each one value; where it sits in its chain is its lineage:
-- a root, under a parent, or minted for a task token from the delegations
-- in delegation_sources.
CREATE TABLE agent_delegations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    delegator_kind text NOT NULL,
    -- no foreign key: the delegator is any principal, by delegator_kind, kept in other contexts' tables or the platform database, and the record outlives it.
    delegator_id uuid NOT NULL,
    delegate_id uuid NOT NULL,
    granted jsonb NOT NULL,
    limits jsonb NOT NULL,
    lineage text NOT NULL,
    parent_id uuid,
    -- Who granted every delegation a minted one was cut from, or NULL for
    -- one not minted.
    minted_delegator_kind text,
    -- no foreign key: the one who granted the sources is any principal, by minted_delegator_kind, kept in other contexts' tables.
    minted_delegator_id uuid,
    depth smallint NOT NULL,
    status text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- When its delegator last renewed it, or NULL when nobody did.
    renewed_at timestamptz,
    updated_at timestamptz NOT NULL,
    name text,
    -- The credential whose key signed the agent in to mint a task token,
    -- kept on the minted delegation. A bound token is bound to that key and
    -- no other, and stands only while that credential is not revoked.
    minted_credential_id uuid,
    CONSTRAINT agent_delegations_tenant_id_key UNIQUE (tenant_id, id),
    -- What an agent holds goes with the agent.
    CONSTRAINT agent_delegations_delegate_fkey FOREIGN KEY (tenant_id, delegate_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    -- A sub-delegation is cut from its parent, and goes with it.
    CONSTRAINT agent_delegations_parent_fkey FOREIGN KEY (tenant_id, parent_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_delegations_delegator_kind_known
        CHECK (delegator_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT agent_delegations_minted_delegator_kind_known
        CHECK (minted_delegator_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT agent_delegations_lineage_known CHECK (lineage IN ('root', 'under', 'minted')),
    -- A token minted with a key goes with that key.
    CONSTRAINT agent_delegations_minted_credential_fkey
        FOREIGN KEY (tenant_id, minted_credential_id)
        REFERENCES agent_credentials (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_delegations_lineage_fits_columns CHECK (
        (lineage = 'root'
            AND num_nonnulls(parent_id, minted_delegator_kind, minted_delegator_id,
                             minted_credential_id) = 0)
        OR (lineage = 'under' AND parent_id IS NOT NULL
            AND num_nonnulls(minted_delegator_kind, minted_delegator_id, minted_credential_id) = 0)
        OR (lineage = 'minted' AND parent_id IS NULL
            AND num_nonnulls(minted_delegator_kind, minted_delegator_id, minted_credential_id) = 3)
    ),
    CONSTRAINT agent_delegations_not_under_itself CHECK (parent_id <> id),
    CONSTRAINT agent_delegations_depth_known CHECK (depth BETWEEN 0 AND 255),
    CONSTRAINT agent_delegations_status_known CHECK (status IN ('active', 'revoked')),
    CONSTRAINT agent_delegations_expires_after_issued CHECK (expires_at > issued_at),
    CONSTRAINT agent_delegations_renewed_after_issued CHECK (renewed_at >= issued_at),
    CONSTRAINT agent_delegations_changed_after_issued CHECK (updated_at >= issued_at)
);

ALTER TABLE agent_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_delegations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_delegations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX agent_delegations_of_delegate
    ON agent_delegations (tenant_id, delegate_id, issued_at, id);
CREATE INDEX agent_delegations_of_delegator
    ON agent_delegations (tenant_id, delegator_kind, delegator_id, issued_at, id);
-- The children of a delegation, the first step of every revoke.
CREATE INDEX agent_delegations_under ON agent_delegations (tenant_id, parent_id);
-- The delegations a key minted, every row, so revoking or deleting the key
-- never reads the whole table.
CREATE INDEX agent_delegations_minted_with
    ON agent_delegations (tenant_id, minted_credential_id);

-- The named resources each delegation grants a relation on, as its
-- granted value lists them, kept beside it so the agents holding rights
-- on one resource are read from an index.
CREATE TABLE delegation_resources (
    tenant_id uuid NOT NULL,
    delegation_id uuid NOT NULL,
    relation text NOT NULL,
    resource_ref text NOT NULL,
    PRIMARY KEY (tenant_id, delegation_id, relation, resource_ref),
    -- They are part of the delegation, and go with it.
    CONSTRAINT delegation_resources_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE delegation_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON delegation_resources
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX delegation_resources_on ON delegation_resources (tenant_id, resource_ref, delegation_id);

-- The delegations a minted one was cut from, each at its place in its
-- lineage.
CREATE TABLE delegation_sources (
    tenant_id uuid NOT NULL,
    delegation_id uuid NOT NULL,
    source_id uuid NOT NULL,
    position integer NOT NULL,
    PRIMARY KEY (tenant_id, delegation_id, source_id),
    -- The lineage is part of the minted delegation, and goes with it.
    CONSTRAINT delegation_sources_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE,
    -- A source is held by the same agent as the token minted from it, so
    -- it goes only with that agent, and the minted delegation with it.
    CONSTRAINT delegation_sources_source_fkey FOREIGN KEY (tenant_id, source_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT delegation_sources_not_itself CHECK (source_id <> delegation_id)
);

ALTER TABLE delegation_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON delegation_sources
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- What a revoke of one delegation reaches through the tokens minted
-- from it.
CREATE INDEX delegation_sources_from ON delegation_sources (tenant_id, source_id);

-- Which delegations a token exchange derived a delegation's authority
-- from, recorded beside the delegation so revoking a source reaches it.
CREATE TABLE delegation_provenance (
    tenant_id uuid NOT NULL,
    delegation_id uuid NOT NULL,
    source_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, delegation_id, source_id),
    -- The record is about the derived delegation, and goes with it.
    CONSTRAINT delegation_provenance_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE,
    -- Authority derived from a source that is gone has nothing to stand
    -- on; the record goes with the source.
    CONSTRAINT delegation_provenance_source_fkey FOREIGN KEY (tenant_id, source_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE delegation_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_provenance FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON delegation_provenance
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX delegation_provenance_from ON delegation_provenance (tenant_id, source_id);

-- The delegations agents ask people for, kept until the person answers
-- or the request lapses.
CREATE TABLE delegation_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    asked_of_kind text NOT NULL,
    -- no foreign key: the person asked is a tenant user or an organization member, by asked_of_kind, and an organization member lives in the platform database.
    asked_of_id uuid NOT NULL,
    asked_of_person text NOT NULL,
    granted jsonb NOT NULL,
    limits jsonb NOT NULL,
    reason text NOT NULL,
    state text NOT NULL,
    -- The delegation an approved request became, or NULL.
    delegation_id uuid,
    -- When it was answered, or NULL while it waits.
    decided_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A request is its agent's, and goes with it.
    CONSTRAINT delegation_requests_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    -- The delegation a request became is held by the same agent, so it
    -- goes only with that agent, and the request with it.
    CONSTRAINT delegation_requests_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT delegation_requests_asked_of_kind_known
        CHECK (asked_of_kind IN ('user', 'org_user')),
    CONSTRAINT delegation_requests_state_known CHECK (state IN ('pending', 'approved', 'denied')),
    CONSTRAINT delegation_requests_delegation_fits_state
        CHECK ((state = 'approved') = (delegation_id IS NOT NULL)),
    CONSTRAINT delegation_requests_decided_fits_state
        CHECK ((state = 'pending') = (decided_at IS NULL)),
    CONSTRAINT delegation_requests_lapses_after_made CHECK (expires_at > created_at),
    CONSTRAINT delegation_requests_decided_after_made CHECK (decided_at >= created_at),
    CONSTRAINT delegation_requests_changed_after_made CHECK (updated_at >= created_at)
);

ALTER TABLE delegation_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON delegation_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX delegation_requests_of_agent
    ON delegation_requests (tenant_id, agent_id, created_at, id);
CREATE INDEX delegation_requests_asked_of
    ON delegation_requests (tenant_id, asked_of_kind, asked_of_id, created_at, id);
CREATE INDEX delegation_requests_became ON delegation_requests (tenant_id, delegation_id);

-- The task templates one person proposes and a second approves, with the
-- bounds they put on every delegation granted under them.
CREATE TABLE agent_task_templates (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    purpose text NOT NULL,
    purpose_digest bytea NOT NULL,
    ceiling jsonb NOT NULL,
    action_classes jsonb NOT NULL,
    max_ttl_seconds bigint NOT NULL,
    max_depth smallint NOT NULL,
    max_data_class text NOT NULL,
    resource_scope jsonb NOT NULL,
    budget jsonb NOT NULL,
    approval text NOT NULL,
    proposed_by_kind text NOT NULL,
    -- no foreign key: the proposer is a tenant user or an organization member, by proposed_by_kind, and the record outlives the account.
    proposed_by_id uuid NOT NULL,
    proposed_by_person text NOT NULL,
    proposed_at timestamptz NOT NULL,
    -- Who approved it and when, or NULL while nobody has.
    approved_by_kind text,
    -- no foreign key: the approver is a tenant user or an organization member, by approved_by_kind, and the record outlives the account.
    approved_by_id uuid,
    approved_by_person text,
    approved_at timestamptz,
    -- When it was withdrawn, or NULL while it stands.
    retired_at timestamptz,
    CONSTRAINT agent_task_templates_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT agent_task_templates_digest_whole CHECK (octet_length(purpose_digest) = 32),
    CONSTRAINT agent_task_templates_lifetime_known
        CHECK (max_ttl_seconds BETWEEN 1 AND 4294967295),
    CONSTRAINT agent_task_templates_depth_known CHECK (max_depth BETWEEN 0 AND 255),
    CONSTRAINT agent_task_templates_data_class_known
        CHECK (max_data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_task_templates_approval_known
        CHECK (approval IN ('not_required', 'per_action')),
    CONSTRAINT agent_task_templates_proposed_by_kind_known
        CHECK (proposed_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_task_templates_approved_by_kind_known
        CHECK (approved_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_task_templates_approval_whole CHECK (
        num_nonnulls(approved_by_kind, approved_by_id, approved_by_person, approved_at) IN (0, 4)
    ),
    CONSTRAINT agent_task_templates_approved_after_proposed CHECK (approved_at >= proposed_at),
    CONSTRAINT agent_task_templates_retired_after_proposed CHECK (retired_at >= proposed_at)
);

ALTER TABLE agent_task_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_task_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_task_templates
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX agent_task_templates_by_proposed
    ON agent_task_templates (tenant_id, proposed_at, id);

-- Who holds which relation on which named resource, such as the use of a
-- model provider or a tool: what delegation consults before a principal
-- hands a resource on.
CREATE TABLE resource_grants (
    tenant_id uuid NOT NULL,
    subject_kind text NOT NULL,
    -- no foreign key: the holder is any principal, by subject_kind, kept in other contexts' tables or the platform database.
    subject_id uuid NOT NULL,
    relation text NOT NULL,
    object_ref text NOT NULL,
    granted_by_kind text NOT NULL,
    -- no foreign key: the one who granted it is any principal, by granted_by_kind, and the record outlives it.
    granted_by_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, subject_kind, subject_id, relation, object_ref),
    CONSTRAINT resource_grants_subject_kind_known
        CHECK (subject_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT resource_grants_granted_by_kind_known
        CHECK (granted_by_kind IN ('user', 'org_user', 'agent', 'consumer'))
);

ALTER TABLE resource_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON resource_grants
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The agents seen at work that nobody registered, one per source and
-- fingerprint.
CREATE TABLE agent_sightings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source text NOT NULL,
    fingerprint text NOT NULL,
    calls_itself text NOT NULL,
    seen_count bigint NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    state text NOT NULL,
    -- The agent it was registered as, or NULL.
    registered_agent_id uuid,
    -- When a person dealt with it, or NULL while nobody has.
    decided_at timestamptz,
    updated_at timestamptz NOT NULL,
    CONSTRAINT agent_sightings_fingerprint_key UNIQUE (tenant_id, source, fingerprint),
    -- A sighting registered as an agent goes with that agent, so a caller
    -- still at work once the agent is deleted is sighted afresh.
    CONSTRAINT agent_sightings_agent_fkey FOREIGN KEY (tenant_id, registered_agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_sightings_source_known
        CHECK (source IN ('gateway', 'oauth_client', 'cloud_scan')),
    CONSTRAINT agent_sightings_state_known
        CHECK (state IN ('unreviewed', 'registered', 'dismissed')),
    CONSTRAINT agent_sightings_agent_fits_state
        CHECK ((state = 'registered') = (registered_agent_id IS NOT NULL)),
    CONSTRAINT agent_sightings_decided_fits_state
        CHECK ((state = 'unreviewed') = (decided_at IS NULL)),
    CONSTRAINT agent_sightings_seen CHECK (seen_count BETWEEN 1 AND 4294967295),
    CONSTRAINT agent_sightings_last_after_first CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT agent_sightings_changed_after_seen CHECK (updated_at >= last_seen_at),
    CONSTRAINT agent_sightings_decided_after_seen CHECK (decided_at >= first_seen_at)
);

ALTER TABLE agent_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sightings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_sightings
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX agent_sightings_by_last_seen ON agent_sightings (tenant_id, last_seen_at, id);
CREATE INDEX agent_sightings_registered_as ON agent_sightings (tenant_id, registered_agent_id);

-- The most sensitive data each agent has touched, by its rank from 0 for
-- public to 3 for restricted, so the check and the raise are one
-- statement. An agent with no row has touched nothing.
CREATE TABLE agent_exposure (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    level smallint NOT NULL,
    PRIMARY KEY (tenant_id, agent_id),
    -- The mark is the agent's, and goes with it.
    CONSTRAINT agent_exposure_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_exposure_level_known CHECK (level BETWEEN 0 AND 3)
);

ALTER TABLE agent_exposure ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_exposure FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_exposure
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The assertions each agent of a tenant already signed in with, each kept
-- until it would have expired anyway. A captured assertion signs its agent
-- in until it expires, so each is taken once.
CREATE TABLE agent_assertions (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    -- The assertion's own id.
    jti text NOT NULL,
    -- When the assertion stops being taken, and can be forgotten.
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, jti),
    -- An assertion signs in only its agent, so it goes with it.
    CONSTRAINT agent_assertions_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_assertions_id_named CHECK (jti <> '')
);

ALTER TABLE agent_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_assertions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The tenant's spent assertions by expiry, forgotten once it passed.
CREATE INDEX agent_assertions_expiring ON agent_assertions (tenant_id, expires_at);
