-- What a tenant's agents work with and what they did: the model providers
-- and tools a tenant gives its agents, the runs they make with every step
-- they took, the orders that stop a run, the review assignments people
-- make between agents, and the approvals people give an agent's paused
-- actions.
--
-- Every table is a tenant table: it lives in the platform database and in
-- a tenant's own, so it names no platform table. Row-level security keeps
-- each row to its tenant, and every foreign key carries the tenant too, so
-- a row can never point at another tenant's.
--
-- An agent is deleted only once it is revoked, and everything stored
-- against it goes with it: its runs, the reviews it is part of and the
-- approvals of its actions.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

-- The language models a tenant brings for its agents' runs.
CREATE TABLE agent_model_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    endpoint text NOT NULL,
    model text NOT NULL,
    -- The price of a million tokens sent and written, in millionths of the
    -- tenant's billing currency, or neither when nobody set one.
    input_price_micros bigint,
    output_price_micros bigint,
    -- The API key in the sealed form the app's secret sealer gave it, never
    -- in clear, or NULL for an endpoint that takes none.
    api_key_sealed text,
    clearance text NOT NULL,
    status text NOT NULL,
    -- The last test: its outcome, when it ran, and why it failed.
    last_test_status text,
    last_tested_at timestamptz,
    last_test_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- The embedding model it offers beside its chat model, which fills
    -- memories, or NULL for none.
    embedding_model text,
    CONSTRAINT agent_model_providers_kind_known
        CHECK (kind IN ('self_hosted', 'openai', 'anthropic')),
    CONSTRAINT agent_model_providers_anthropic_embeds_nothing
        CHECK (kind <> 'anthropic' OR embedding_model IS NULL),
    CONSTRAINT agent_model_providers_price_whole
        CHECK (num_nulls(input_price_micros, output_price_micros) IN (0, 2)),
    CONSTRAINT agent_model_providers_price_not_negative
        CHECK (input_price_micros >= 0 AND output_price_micros >= 0),
    CONSTRAINT agent_model_providers_clearance_known
        CHECK (clearance IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_model_providers_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT agent_model_providers_test_whole
        CHECK ((last_test_status IS NULL AND last_tested_at IS NULL AND last_test_reason IS NULL)
            OR (last_test_status = 'passed' AND last_tested_at IS NOT NULL
                AND last_test_reason IS NULL)
            OR (last_test_status = 'failed' AND last_tested_at IS NOT NULL)),
    CONSTRAINT agent_model_providers_tested_after_created
        CHECK (last_tested_at IS NULL OR last_tested_at >= created_at),
    CONSTRAINT agent_model_providers_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE agent_model_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_model_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_model_providers
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's providers, oldest first.
CREATE INDEX agent_model_providers_by_created
    ON agent_model_providers (tenant_id, created_at, id);

-- The APIs a tenant's agents may call, each through one route.
CREATE TABLE agent_tools (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    input_schema text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    route_id uuid NOT NULL,
    -- The class the route declares, or NULL when it declares none.
    declared_action text,
    action_class text NOT NULL,
    data_class text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- A tool calls through its route and reaches nothing once the route is
    -- gone, so it goes with it. A route is disabled before it is deleted,
    -- so no live call loses its tool.
    CONSTRAINT agent_tools_route_fkey FOREIGN KEY (tenant_id, route_id)
        REFERENCES routes (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_tools_method_known
        CHECK (method IN ('get', 'post', 'put', 'patch', 'delete')),
    CONSTRAINT agent_tools_declared_action_known
        CHECK (declared_action IN ('read', 'write', 'delete', 'configure', 'communicate',
                                   'financial', 'admin')),
    CONSTRAINT agent_tools_action_class_known
        CHECK (action_class IN ('read', 'write', 'delete', 'configure', 'communicate',
                                'financial', 'admin')),
    CONSTRAINT agent_tools_data_class_known
        CHECK (data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_tools_status_known
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT agent_tools_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE agent_tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_tools FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_tools
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- A tenant's tools, oldest first.
CREATE INDEX agent_tools_by_created ON agent_tools (tenant_id, created_at, id);

-- The tools of one route, and the foreign key to it.
CREATE INDEX agent_tools_of_route ON agent_tools (tenant_id, route_id);

-- The runs of a tenant's agents. A run's steps are rows of their own, so a
-- step is written once and never again.
CREATE TABLE agent_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    -- no foreign key: a run keeps the provider it reasoned with as history, after the provider is deleted.
    provider_id uuid NOT NULL,
    goal text NOT NULL,
    -- The action classes the run's calls may take, the tools it was given
    -- by name, and the classes a person must approve first.
    purpose text[] NOT NULL,
    granted_tools text[] NOT NULL,
    approval_classes text[] NOT NULL,
    -- Whether every call waits for a person, as the delegation asked.
    approval text NOT NULL,
    -- Linked to its delegation in 0026.
    delegation_id uuid,
    max_steps integer NOT NULL,
    -- The most the run may spend on its model, or NULL for no limit.
    spend_limit_micros bigint,
    input_tokens bigint NOT NULL,
    output_tokens bigint NOT NULL,
    spent_micros bigint NOT NULL,
    -- Who started the run: the kind of party and its id, and for a human
    -- the person behind the account.
    started_by_kind text NOT NULL,
    -- no foreign key: the starter is a user, an organization member, an agent or a consumer, by started_by_kind, kept in other contexts' tables.
    started_by_id uuid NOT NULL,
    started_by_person text,
    exposure text NOT NULL,
    -- How deep in a chain of workflows the run was started, or NULL
    -- outside any workflow.
    chain_depth smallint,
    status text NOT NULL,
    -- The call the run holds, paused on or approved to run.
    pending_call jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Where the run waits for a person before it spends more on its
    -- model: it asks once it spent spend_check_micros, is due to ask, or
    -- has asked. Both NULL for a run that never waits over spend.
    spend_check text,
    spend_check_micros bigint,
    -- The sandbox version whose code checks each of the run's answers,
    -- and how many answers it may give; both NULL for a run that completes
    -- on its model's answer.
    -- no foreign key: a run keeps the version its answers were checked by as history, as it keeps its provider.
    check_version_id uuid,
    check_tries smallint,
    CONSTRAINT agent_runs_tenant_id_key UNIQUE (tenant_id, id),
    -- A run is the agent's work, so it goes with the agent.
    CONSTRAINT agent_runs_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_runs_purpose_known
        CHECK (purpose <@ ARRAY['read', 'write', 'delete', 'configure', 'communicate',
                                'financial', 'admin']),
    CONSTRAINT agent_runs_approval_classes_known
        CHECK (approval_classes <@ ARRAY['read', 'write', 'delete', 'configure', 'communicate',
                                         'financial', 'admin']),
    CONSTRAINT agent_runs_approval_known
        CHECK (approval IN ('not_required', 'per_action')),
    CONSTRAINT agent_runs_counts_not_negative
        CHECK (max_steps >= 0 AND spend_limit_micros >= 0 AND input_tokens >= 0
               AND output_tokens >= 0 AND spent_micros >= 0),
    CONSTRAINT agent_runs_starter_known
        CHECK ((started_by_kind IN ('user', 'org_user') AND started_by_person IS NOT NULL)
            OR (started_by_kind IN ('agent', 'consumer') AND started_by_person IS NULL)),
    CONSTRAINT agent_runs_exposure_known
        CHECK (exposure IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_runs_chain_depth_in_range
        CHECK (chain_depth BETWEEN 1 AND 3),
    CONSTRAINT agent_runs_status_known
        CHECK (status IN ('running', 'completed', 'failed', 'cancelled', 'halted',
                          'awaiting_approval', 'paused', 'over_budget')),
    CONSTRAINT agent_runs_paused_on_a_call
        CHECK (status <> 'awaiting_approval' OR pending_call IS NOT NULL),
    CONSTRAINT agent_runs_changed_after_created
        CHECK (updated_at >= created_at),
    CONSTRAINT agent_runs_spend_check_known
        CHECK (spend_check IN ('ask_at', 'due', 'asked')),
    CONSTRAINT agent_runs_spend_check_names_its_amount
        CHECK ((spend_check IS NULL) = (spend_check_micros IS NULL)
               AND spend_check_micros > 0),
    CONSTRAINT agent_runs_check_whole
        CHECK ((check_version_id IS NULL) = (check_tries IS NULL)
               AND check_tries BETWEEN 1 AND 3)
);

ALTER TABLE agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_runs
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An agent's runs, newest first, and the foreign key to the agent; and
-- the same narrowed to one status.
CREATE INDEX agent_runs_of_agent ON agent_runs (tenant_id, agent_id, created_at, id);
CREATE INDEX agent_runs_of_agent_in_status
    ON agent_runs (tenant_id, agent_id, status, created_at, id);

-- Every run of a tenant, newest first, and the same in one status.
CREATE INDEX agent_runs_by_created ON agent_runs (tenant_id, created_at, id);
CREATE INDEX agent_runs_in_status ON agent_runs (tenant_id, status, created_at, id);

-- The runs still running, the oldest first, across every tenant of a
-- database, for the reconcile sweep that hands out again a run no worker
-- drives.
CREATE INDEX agent_runs_running_since ON agent_runs (created_at, id) WHERE status = 'running';

-- The steps of a run, numbered from one. A step is only ever added.
CREATE TABLE agent_run_steps (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    seq integer NOT NULL,
    step jsonb NOT NULL,
    PRIMARY KEY (tenant_id, run_id, seq),
    -- A step is part of its run.
    CONSTRAINT agent_run_steps_run_fkey FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_run_steps_numbered_from_one
        CHECK (seq >= 1)
);

ALTER TABLE agent_run_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_run_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_run_steps
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The order a person gave to stop a run, read by the worker driving it
-- between steps, and forgotten once the run ends.
CREATE TABLE agent_run_cancellations (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    -- The person who gave the order: the account's kind, the account and
    -- the person behind it.
    ordered_by_kind text NOT NULL,
    -- no foreign key: the person stopping a run acts through a user or an organization member, by ordered_by_kind, kept in other contexts' tables.
    ordered_by_id uuid NOT NULL,
    ordered_by_person text NOT NULL,
    ordered_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    -- An order stops one run and means nothing without it.
    CONSTRAINT agent_run_cancellations_run_fkey FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_run_cancellations_orderer_known
        CHECK (ordered_by_kind IN ('user', 'org_user'))
);

ALTER TABLE agent_run_cancellations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_run_cancellations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_run_cancellations
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The assignments people make of one agent to review another.
CREATE TABLE agent_review_assignments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    reviewer_id uuid NOT NULL,
    reviewed_id uuid NOT NULL,
    -- The person who assigned it: the account's kind and the account.
    assigned_by_kind text NOT NULL,
    -- no foreign key: the person assigning a review acts through a user or an organization member, by assigned_by_kind, kept in other contexts' tables.
    assigned_by_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL,
    ended_at timestamptz,
    -- A review is between two agents, so it goes with either of them.
    CONSTRAINT agent_review_assignments_reviewer_fkey FOREIGN KEY (tenant_id, reviewer_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_review_assignments_reviewed_fkey FOREIGN KEY (tenant_id, reviewed_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_review_assignments_assigner_known
        CHECK (assigned_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_review_assignments_not_itself
        CHECK (reviewer_id <> reviewed_id),
    CONSTRAINT agent_review_assignments_ended_after_assigned
        CHECK (ended_at IS NULL OR ended_at >= assigned_at)
);

ALTER TABLE agent_review_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_review_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_review_assignments
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- The assignments an agent reviews in, and those it is reviewed in, newest
-- first, each with its foreign key.
CREATE INDEX agent_review_assignments_of_reviewer
    ON agent_review_assignments (tenant_id, reviewer_id, assigned_at, id);
CREATE INDEX agent_review_assignments_of_reviewed
    ON agent_review_assignments (tenant_id, reviewed_id, assigned_at, id);

-- The requests for a person to approve one action an agent wants to take.
CREATE TABLE agent_approvals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    -- Linked to its delegation in 0026.
    delegation_id uuid,
    -- Who put the action there: the person or machine who opened the
    -- request, or who started the run that raised it.
    requested_by_kind text NOT NULL,
    -- no foreign key: the requester is a user, an organization member, an agent or a consumer, by requested_by_kind, kept in other contexts' tables.
    requested_by_id uuid NOT NULL,
    requested_by_person text,
    -- The run that raised the request, the call it paused on and what it
    -- had read, or none of them for a request opened by hand.
    run_id uuid,
    pending_tool text,
    pending_arguments text,
    pending_at_step integer,
    run_exposure text,
    chain_depth smallint,
    -- The agent's owner; the people behind the delegation are rows of
    -- agent_approval_delegators.
    owner_kind text NOT NULL,
    -- no foreign key: the owner acts through a user or an organization member, by owner_kind, kept in other contexts' tables.
    owner_id uuid NOT NULL,
    owner_person text NOT NULL,
    -- The class of the paused action, or NULL when it is not known.
    action_class text,
    action text NOT NULL,
    status text NOT NULL,
    -- The first of two approvals, when one was given.
    first_by_kind text,
    -- no foreign key: an approver acts through a user or an organization member, by first_by_kind, kept in other contexts' tables.
    first_by_id uuid,
    first_by_person text,
    first_at timestamptz,
    -- Who decided and when: the approval that granted it, or who denied or
    -- withdrew it.
    decided_by_kind text,
    -- no foreign key: a decider acts through a user or an organization member, by decided_by_kind, kept in other contexts' tables.
    decided_by_id uuid,
    decided_by_person text,
    decided_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT agent_approvals_tenant_id_key UNIQUE (tenant_id, id),
    -- A request is about the agent's action, so it goes with the agent.
    CONSTRAINT agent_approvals_agent_fkey FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agents (tenant_id, id) ON DELETE CASCADE,
    -- A run's request is about the call the run holds, so it goes with the
    -- run.
    CONSTRAINT agent_approvals_run_fkey FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_approvals_requester_known
        CHECK ((requested_by_kind IN ('user', 'org_user') AND requested_by_person IS NOT NULL)
            OR (requested_by_kind IN ('agent', 'consumer') AND requested_by_person IS NULL)),
    CONSTRAINT agent_approvals_run_whole
        CHECK ((run_id IS NULL
                AND num_nonnulls(pending_tool, pending_arguments, pending_at_step, run_exposure,
                                 chain_depth) = 0)
            OR (run_id IS NOT NULL
                AND num_nonnulls(pending_tool, pending_arguments, pending_at_step,
                                 run_exposure) = 4)),
    CONSTRAINT agent_approvals_run_has_a_class
        CHECK (run_id IS NULL OR action_class IS NOT NULL),
    CONSTRAINT agent_approvals_run_exposure_known
        CHECK (run_exposure IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT agent_approvals_chain_depth_in_range
        CHECK (chain_depth BETWEEN 1 AND 3),
    CONSTRAINT agent_approvals_owner_known
        CHECK (owner_kind IN ('user', 'org_user')),
    CONSTRAINT agent_approvals_action_class_known
        CHECK (action_class IN ('read', 'write', 'delete', 'configure', 'communicate',
                                'financial', 'admin')),
    CONSTRAINT agent_approvals_status_known
        CHECK (status IN ('pending', 'approved', 'consumed', 'denied', 'expired', 'withdrawn')),
    CONSTRAINT agent_approvals_first_whole
        CHECK (num_nulls(first_by_kind, first_by_id, first_by_person, first_at) IN (0, 4)),
    CONSTRAINT agent_approvals_first_by_a_person
        CHECK (first_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_approvals_decision_whole
        CHECK (num_nulls(decided_by_kind, decided_by_id, decided_by_person, decided_at) IN (0, 4)),
    CONSTRAINT agent_approvals_decided_by_a_person
        CHECK (decided_by_kind IN ('user', 'org_user')),
    CONSTRAINT agent_approvals_decision_fits_status
        CHECK ((status IN ('pending', 'expired')) = (decided_at IS NULL)),
    CONSTRAINT agent_approvals_withdrawn_with_its_run
        CHECK (status <> 'withdrawn' OR run_id IS NOT NULL),
    CONSTRAINT agent_approvals_expire_after_created
        CHECK (expires_at > created_at),
    CONSTRAINT agent_approvals_changed_after_created
        CHECK (updated_at >= created_at)
);

ALTER TABLE agent_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_approvals
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- An agent's requests, newest first, and the foreign key to the agent.
CREATE INDEX agent_approvals_of_agent ON agent_approvals (tenant_id, agent_id, created_at, id);

-- Every request of a tenant, newest first.
CREATE INDEX agent_approvals_by_created ON agent_approvals (tenant_id, created_at, id);

-- The requests of one run, and the foreign key to it.
CREATE INDEX agent_approvals_of_run ON agent_approvals (tenant_id, run_id);

-- The open or granted request for one action under one delegation, read
-- on every gated call.
CREATE INDEX agent_approvals_for_action
    ON agent_approvals (tenant_id, delegation_id, status, action);

-- What one person signed, for the cap on approvals per person.
CREATE INDEX agent_approvals_decided_by
    ON agent_approvals (tenant_id, decided_by_kind, decided_by_id, decided_at);
CREATE INDEX agent_approvals_first_by
    ON agent_approvals (tenant_id, first_by_kind, first_by_id, first_at);

-- The people behind the delegation a request's action uses, in the order
-- the request names them. None of them may approve it.
CREATE TABLE agent_approval_delegators (
    tenant_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    place smallint NOT NULL,
    account_kind text NOT NULL,
    -- no foreign key: a delegator acts through a user or an organization member, by account_kind, kept in other contexts' tables.
    account_id uuid NOT NULL,
    person text NOT NULL,
    PRIMARY KEY (tenant_id, approval_id, place),
    -- The people behind a request are part of it.
    CONSTRAINT agent_approval_delegators_approval_fkey FOREIGN KEY (tenant_id, approval_id)
        REFERENCES agent_approvals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_approval_delegators_account_known
        CHECK (account_kind IN ('user', 'org_user')),
    CONSTRAINT agent_approval_delegators_place_not_negative
        CHECK (place >= 0)
);

ALTER TABLE agent_approval_delegators ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_approval_delegators FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON agent_approval_delegators
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));
