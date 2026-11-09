-- The authorization context: a tenant's roles, groups, who holds them, the
-- resource types its app declares, relationships on the app's objects, the
-- versions of its access policy, access requests and reviews, separation
-- and clearance rules, break-glass grants and the record of every decision.
--
-- These are tenant tables: they live in the platform database and in a
-- tenant's own database alike, which has no tenants table, so none of them
-- points at one. Every table is under row-level security, and every foreign
-- key between them carries tenant_id, so no row can point at another
-- tenant's.
--
-- A principal is stored as a kind and an id. The kinds are the words of
-- postgres/authorization/principals.rs: user, org_user, agent, consumer.
--
-- The checks repeat the rules the domain keeps between columns, so a row
-- written past the domain is refused here too.

CREATE TABLE roles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    -- Built-in permissions, each written as `idp:area:action`.
    system_permissions text[] NOT NULL,
    -- The tenant's own permissions, each written as `resource:action`.
    custom_permissions text[] NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT roles_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT roles_name_key UNIQUE (tenant_id, name),
    CONSTRAINT roles_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON roles
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX roles_by_created ON roles (tenant_id, created_at, id);
CREATE INDEX roles_by_updated ON roles (tenant_id, updated_at, id);
CREATE INDEX roles_by_name ON roles (tenant_id, name, id);
CREATE INDEX roles_given_to_new_users ON roles (tenant_id) WHERE is_default;

CREATE TABLE role_assignments (
    tenant_id uuid NOT NULL,
    role_id uuid NOT NULL,
    principal_kind text NOT NULL,
    -- no foreign key: a principal is a user, an organization member, an agent or a consumer, by principal_kind, kept in other contexts' tables.
    principal_id uuid NOT NULL,
    -- Who gave it, as the domain writes an actor.
    assigned_by jsonb NOT NULL,
    assigned_at timestamptz NOT NULL,
    -- When it ends, or NULL when it does not.
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, role_id, principal_kind, principal_id),
    -- An assignment of a role that is gone gives nothing, so it goes with
    -- the role. Deleting a role first moves or refuses its holders.
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_principal_kind_known
        CHECK (principal_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT role_assignments_ends_after_given
        CHECK (expires_at IS NULL OR expires_at > assigned_at)
);

ALTER TABLE role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON role_assignments
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- What one principal holds, read on every access check.
CREATE INDEX role_assignments_of_principal
    ON role_assignments (tenant_id, principal_kind, principal_id);
-- Who holds one role, in the order its holders are listed.
CREATE INDEX role_assignments_holders ON role_assignments (tenant_id, role_id, principal_id);
-- The assignments that end, for the sweep that clears them away.
CREATE INDEX role_assignments_ending ON role_assignments (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;
-- The whole key after the expiry, so a bounded sweep moves on through
-- equal expiry times without sorting every expired holding again.
CREATE INDEX role_assignments_sweep
    ON role_assignments (tenant_id, expires_at, role_id, principal_kind, principal_id)
    WHERE expires_at IS NOT NULL;

CREATE TABLE groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    origin text NOT NULL,
    -- The group it sits under, or NULL at the top of the tree.
    parent_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT groups_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT groups_name_key UNIQUE (tenant_id, name),
    -- A group with groups under it is never deleted: the domain refuses,
    -- so a subgroup is never left under a group that is gone.
    FOREIGN KEY (tenant_id, parent_id) REFERENCES groups (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT groups_origin_known CHECK (origin IN ('directory', 'dashboard')),
    CONSTRAINT groups_not_under_itself CHECK (parent_id IS DISTINCT FROM id),
    CONSTRAINT groups_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON groups
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX groups_by_created ON groups (tenant_id, created_at, id);
CREATE INDEX groups_by_updated ON groups (tenant_id, updated_at, id);
CREATE INDEX groups_by_name ON groups (tenant_id, name, id);
CREATE INDEX groups_under_parent ON groups (tenant_id, parent_id);

-- The roles each group carries, in the order they were given.
CREATE TABLE group_roles (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    role_id uuid NOT NULL,
    position integer NOT NULL,
    PRIMARY KEY (tenant_id, group_id, role_id),
    -- The roles a group carries are part of the group, and go with it.
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    -- A role a group still carries is never deleted: the domain refuses,
    -- so a group never silently loses what it gives its members.
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE group_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON group_roles
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX group_roles_carrying ON group_roles (tenant_id, role_id, group_id);

CREATE TABLE group_memberships (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    principal_kind text NOT NULL,
    -- no foreign key: a principal is a user, an organization member, an agent or a consumer, by principal_kind, kept in other contexts' tables.
    principal_id uuid NOT NULL,
    joined_at timestamptz NOT NULL,
    -- When it ends, or NULL when it does not.
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, group_id, principal_kind, principal_id),
    -- A place in a group that is gone means nothing, so it goes with it.
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT group_memberships_principal_kind_known
        CHECK (principal_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT group_memberships_ends_after_joined
        CHECK (expires_at IS NULL OR expires_at > joined_at)
);

ALTER TABLE group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON group_memberships
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX group_memberships_of_principal
    ON group_memberships (tenant_id, principal_kind, principal_id);
-- A group's members, oldest membership first.
CREATE INDEX group_memberships_by_joined
    ON group_memberships (tenant_id, group_id, joined_at, principal_id);
CREATE INDEX group_memberships_ending ON group_memberships (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX group_memberships_sweep
    ON group_memberships (tenant_id, expires_at, group_id, principal_kind, principal_id)
    WHERE expires_at IS NOT NULL;

-- Who holds each role: those given it straight, as kind 0, and the groups
-- carrying it, as kind 1, so one keyset page walks both. It reads as the
-- caller, so row-level security applies through it.
CREATE VIEW role_holders WITH (security_invoker = true) AS
    SELECT tenant_id, role_id, 0::bigint AS kind, principal_kind,
           principal_id AS holder_id, expires_at
    FROM role_assignments
    UNION ALL
    SELECT tenant_id, role_id, 1::bigint AS kind, NULL::text AS principal_kind,
           group_id AS holder_id, NULL::timestamptz AS expires_at
    FROM group_roles;

CREATE TABLE resource_types (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    key text NOT NULL,
    display_name text NOT NULL,
    description text,
    -- The actions it declares and what each brings, as the domain writes
    -- them.
    actions jsonb NOT NULL,
    data_class text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT resource_types_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT resource_types_key_key UNIQUE (tenant_id, key),
    CONSTRAINT resource_types_data_class_known
        CHECK (data_class IN ('public', 'internal', 'confidential', 'restricted')),
    CONSTRAINT resource_types_changed_after_created CHECK (updated_at >= created_at)
);

ALTER TABLE resource_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_types FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON resource_types
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX resource_types_by_created ON resource_types (tenant_id, created_at, id);
CREATE INDEX resource_types_by_updated ON resource_types (tenant_id, updated_at, id);
CREATE INDEX resource_types_by_key ON resource_types (tenant_id, key, id);

-- One fact about an object of the tenant's app: someone holds a relation
-- on it, or it sits under another object.
CREATE TABLE relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    object_type text NOT NULL,
    object_key text NOT NULL,
    link text NOT NULL,
    relation text,
    subject_kind text,
    -- no foreign key: the subject is a principal kept in another context's table, or a group, by subject_kind.
    subject_id uuid,
    parent_type text,
    parent_key text,
    created_at timestamptz NOT NULL,
    CONSTRAINT relationships_fact_key UNIQUE NULLS NOT DISTINCT
        (tenant_id, object_type, object_key, link, relation, subject_kind, subject_id,
         parent_type, parent_key),
    CONSTRAINT relationships_link_known CHECK (link IN ('holds', 'under')),
    CONSTRAINT relationships_subject_kind_known
        CHECK (subject_kind IN ('user', 'org_user', 'agent', 'consumer', 'group')),
    CONSTRAINT relationships_link_fits_columns CHECK (
        (link = 'holds'
            AND num_nonnulls(relation, subject_kind, subject_id) = 3
            AND num_nonnulls(parent_type, parent_key) = 0)
        OR (link = 'under'
            AND num_nonnulls(relation, subject_kind, subject_id) = 0
            AND num_nonnulls(parent_type, parent_key) = 2)),
    CONSTRAINT relationships_not_under_itself
        CHECK (link <> 'under' OR (parent_type, parent_key) <> (object_type, object_key))
);

ALTER TABLE relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON relationships
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX relationships_by_created ON relationships (tenant_id, created_at, id);
-- The relationships on one object, newest first, and the walk up its
-- parents an access check makes.
CREATE INDEX relationships_on_object
    ON relationships (tenant_id, object_type, object_key, created_at, id);
CREATE INDEX relationships_held_by
    ON relationships (tenant_id, subject_kind, subject_id, created_at, id)
    WHERE link = 'holds';

-- Every version of a tenant's access policy, by its number.
CREATE TABLE policy_versions (
    tenant_id uuid NOT NULL,
    version integer NOT NULL,
    status text NOT NULL,
    -- What it was started from: blank, a copy of the live version, or a
    -- past version restored, with that version's number.
    based_on text NOT NULL,
    based_on_version integer,
    default_action jsonb NOT NULL,
    rules jsonb NOT NULL,
    -- Who sent it to review, through which account, or NULL for nobody.
    submitted_by_kind text,
    -- no foreign key: the account is a user or an organization member, kept in another context's table, and the record outlives it.
    submitted_by_id uuid,
    submitted_by_person text,
    PRIMARY KEY (tenant_id, version),
    CONSTRAINT policy_versions_version_positive CHECK (version > 0),
    CONSTRAINT policy_versions_status_known
        CHECK (status IN ('draft', 'review', 'active', 'archived')),
    CONSTRAINT policy_versions_based_on_known CHECK (based_on IN ('blank', 'copy', 'restore')),
    CONSTRAINT policy_versions_base_fits_kind
        CHECK ((based_on = 'blank') = (based_on_version IS NULL)),
    CONSTRAINT policy_versions_based_on_earlier
        CHECK (based_on_version IS NULL OR based_on_version < version),
    CONSTRAINT policy_versions_submitter_kind_known
        CHECK (submitted_by_kind IN ('user', 'org_user')),
    CONSTRAINT policy_versions_submitter_whole
        CHECK (num_nonnulls(submitted_by_kind, submitted_by_id, submitted_by_person) IN (0, 3)),
    CONSTRAINT policy_versions_review_was_sent
        CHECK (status <> 'review' OR submitted_by_kind IS NOT NULL)
);

ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON policy_versions
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- At most one live version per tenant, which every request reads, and at
-- most one open draft beside it.
CREATE UNIQUE INDEX policy_versions_one_live ON policy_versions (tenant_id)
    WHERE status = 'active';
CREATE UNIQUE INDEX policy_versions_one_open ON policy_versions (tenant_id)
    WHERE status IN ('draft', 'review');

-- The longest a tenant lets its people ask for access, one row per tenant.
CREATE TABLE access_request_policies (
    tenant_id uuid PRIMARY KEY,
    longest_seconds bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT access_request_policies_longest_known
        CHECK (longest_seconds > 0 AND longest_seconds <= 2592000)
);

ALTER TABLE access_request_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_request_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON access_request_policies
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE TABLE access_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    requester_kind text NOT NULL,
    -- no foreign key: the account is a user or an organization member, kept in another context's table, and the request outlives it.
    requester_id uuid NOT NULL,
    requester_person text NOT NULL,
    asked text NOT NULL,
    -- no foreign key: it names a role or a group, by asked, and the request is kept as asked after either is deleted.
    asked_id uuid NOT NULL,
    reason text NOT NULL,
    length_seconds bigint NOT NULL,
    status text NOT NULL,
    -- Who answered, through which account, and when; all NULL until then.
    approver_kind text,
    -- no foreign key: the account is a user or an organization member, kept in another context's table, and the request outlives it.
    approver_id uuid,
    approver_person text,
    answered_at timestamptz,
    requested_at timestamptz NOT NULL,
    CONSTRAINT access_requests_requester_kind_known
        CHECK (requester_kind IN ('user', 'org_user')),
    CONSTRAINT access_requests_approver_kind_known CHECK (approver_kind IN ('user', 'org_user')),
    CONSTRAINT access_requests_asked_known CHECK (asked IN ('role', 'group')),
    CONSTRAINT access_requests_status_known
        CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
    CONSTRAINT access_requests_length_known
        CHECK (length_seconds > 0 AND length_seconds <= 2592000),
    CONSTRAINT access_requests_answer_whole
        CHECK (num_nonnulls(approver_kind, approver_id, approver_person, answered_at) IN (0, 4)),
    CONSTRAINT access_requests_answer_fits_status
        CHECK ((status IN ('approved', 'denied')) = (answered_at IS NOT NULL)),
    CONSTRAINT access_requests_answered_after_asked
        CHECK (answered_at IS NULL OR answered_at >= requested_at)
);

ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON access_requests
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX access_requests_by_requested ON access_requests (tenant_id, requested_at, id);
-- The pending ones, newest first, and the oldest for the sweep that lets
-- them run out.
CREATE INDEX access_requests_by_status
    ON access_requests (tenant_id, status, requested_at, id);
CREATE INDEX access_requests_asked_by
    ON access_requests (tenant_id, requester_kind, requester_id, requested_at, id);

CREATE TABLE access_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    scope text NOT NULL,
    -- no foreign key: it names a role or a group, by scope, and a review is evidence kept after either is deleted.
    scope_id uuid NOT NULL,
    -- The reviewers, one entry each in the three lists: the account's kind,
    -- the account and the person behind it.
    reviewer_kinds text[] NOT NULL,
    reviewer_ids uuid[] NOT NULL,
    reviewer_persons text[] NOT NULL,
    due timestamptz NOT NULL,
    unanswered text NOT NULL,
    status text NOT NULL,
    started_at timestamptz NOT NULL,
    -- How many holders it lists, how many are undecided and how many are
    -- marked remove, so a list of reviews never reads their holders.
    holder_count bigint NOT NULL,
    pending_count bigint NOT NULL,
    remove_count bigint NOT NULL,
    CONSTRAINT access_reviews_tenant_id_key UNIQUE (tenant_id, id),
    CONSTRAINT access_reviews_scope_known CHECK (scope IN ('role', 'group')),
    CONSTRAINT access_reviews_unanswered_known
        CHECK (unanswered IN ('keep_access', 'remove_access')),
    CONSTRAINT access_reviews_status_known CHECK (status IN ('open', 'completed', 'cancelled')),
    CONSTRAINT access_reviews_reviewers_whole CHECK (
        cardinality(reviewer_kinds) = cardinality(reviewer_ids)
        AND cardinality(reviewer_ids) = cardinality(reviewer_persons)),
    CONSTRAINT access_reviews_due_after_started CHECK (due > started_at),
    CONSTRAINT access_reviews_counts_whole CHECK (
        holder_count > 0 AND pending_count >= 0 AND remove_count >= 0
        AND pending_count <= holder_count AND remove_count <= holder_count - pending_count
    )
);

ALTER TABLE access_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON access_reviews
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX access_reviews_by_started ON access_reviews (tenant_id, started_at, id);
CREATE INDEX access_reviews_by_status ON access_reviews (tenant_id, status, started_at, id);
-- The open ones by their due date and id, for the sweep that completes
-- them, equal due dates included.
CREATE INDEX access_reviews_open_by_due ON access_reviews (tenant_id, due, id)
    WHERE status = 'open';

-- Each holder a review asks about, in the order listed, what was decided
-- and what is suggested: all three reviewer columns NULL while it is
-- pending, and both suggestion columns NULL while nothing is suggested.
CREATE TABLE access_review_items (
    tenant_id uuid NOT NULL,
    review_id uuid NOT NULL,
    position bigint NOT NULL,
    holder_kind text NOT NULL,
    -- no foreign key: a holder is a principal kept in another context's table, and the review is evidence kept after it is gone.
    holder_id uuid NOT NULL,
    choice text,
    reviewer_kind text,
    -- no foreign key: the reviewer's account is kept in another context's table, and the decision is evidence kept after it is gone.
    reviewer_id uuid,
    reviewer_person text,
    -- Keep or remove suggested beside the holder, with a reason the
    -- reviewer reads; the reviewer still decides.
    suggested_choice text,
    suggested_reason text,
    PRIMARY KEY (tenant_id, review_id, position),
    -- The holders are part of the review, and go with it.
    FOREIGN KEY (tenant_id, review_id) REFERENCES access_reviews (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT access_review_items_holder_known
        UNIQUE (tenant_id, review_id, holder_kind, holder_id),
    CONSTRAINT access_review_items_holder_kind_known
        CHECK (holder_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT access_review_items_choice_known CHECK (choice IN ('keep', 'remove')),
    CONSTRAINT access_review_items_reviewer_kind_known
        CHECK (reviewer_kind IN ('user', 'org_user')),
    CONSTRAINT access_review_items_decision_whole
        CHECK (num_nonnulls(choice, reviewer_kind, reviewer_id, reviewer_person) IN (0, 4)),
    CONSTRAINT access_review_items_positive_position CHECK (position > 0),
    CONSTRAINT access_review_items_suggested_choice_known
        CHECK (suggested_choice IN ('keep', 'remove')),
    CONSTRAINT access_review_items_suggestion_whole
        CHECK (num_nonnulls(suggested_choice, suggested_reason) IN (0, 2))
);

ALTER TABLE access_review_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_review_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON access_review_items
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE TABLE separation_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    first_role_id uuid NOT NULL,
    second_role_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    -- A rule keeping a deleted role apart keeps nothing apart, so it goes
    -- with either role.
    FOREIGN KEY (tenant_id, first_role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE,
    -- The same for the second role.
    FOREIGN KEY (tenant_id, second_role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT separation_rules_two_roles CHECK (first_role_id <> second_role_id)
);

ALTER TABLE separation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE separation_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON separation_rules
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX separation_rules_by_created ON separation_rules (tenant_id, created_at, id);
CREATE INDEX separation_rules_first_role ON separation_rules (tenant_id, first_role_id);
CREATE INDEX separation_rules_second_role ON separation_rules (tenant_id, second_role_id);

-- Which app permissions clear their holders for which data, one row per
-- tenant: entry n of the two lists is one rule.
CREATE TABLE clearance_rules (
    tenant_id uuid PRIMARY KEY,
    permissions text[] NOT NULL,
    levels text[] NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT clearance_rules_whole CHECK (cardinality(permissions) = cardinality(levels)),
    CONSTRAINT clearance_rules_levels_known
        CHECK (levels <@ ARRAY['confidential', 'restricted']::text[])
);

ALTER TABLE clearance_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE clearance_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON clearance_rules
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Emergency access granted to a user for a short window. The access
-- records read the running ones on every check.
CREATE TABLE break_glass_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- The account it is given to, linked to users in 0010.
    user_id uuid NOT NULL,
    grantee_person text NOT NULL,
    system_permissions text[] NOT NULL,
    custom_permissions text[] NOT NULL,
    reason text NOT NULL,
    -- Who approved it, through which account, or all NULL when the user
    -- approved it themselves.
    approver_kind text,
    -- no foreign key: the account is a user or an organization member, kept in another context's table, and the grant outlives it.
    approver_id uuid,
    approver_person text,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT break_glass_grants_approver_kind_known
        CHECK (approver_kind IN ('user', 'org_user')),
    CONSTRAINT break_glass_grants_approver_whole
        CHECK (num_nonnulls(approver_kind, approver_id, approver_person) IN (0, 3)),
    CONSTRAINT break_glass_grants_grants_something
        CHECK (cardinality(system_permissions) + cardinality(custom_permissions) > 0),
    CONSTRAINT break_glass_grants_ends_after_created CHECK (expires_at > created_at),
    CONSTRAINT break_glass_grants_revoked_after_created
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

ALTER TABLE break_glass_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE break_glass_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON break_glass_grants
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

CREATE INDEX break_glass_grants_of_user ON break_glass_grants (tenant_id, user_id, expires_at);
CREATE INDEX break_glass_grants_by_created ON break_glass_grants (tenant_id, created_at, id);

-- The answer to every access check and every request the policy decided,
-- kept as evidence: never changed, never deleted.
CREATE TABLE decision_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    -- Who asked, as the domain writes an actor.
    asked_by jsonb NOT NULL,
    subject_kind text NOT NULL,
    -- no foreign key: the subject is a principal kept in another context's table, and the record is evidence kept after it is gone.
    subject_id uuid NOT NULL,
    verdict text NOT NULL,
    -- The policy version and rule that decided, kept beside the basis so a
    -- search reads an index: both NULL for an app's check, and the rule
    -- NULL when the policy's default decided.
    policy_version integer,
    rule text,
    basis jsonb NOT NULL,
    decided_at timestamptz NOT NULL,
    CONSTRAINT decision_records_subject_kind_known
        CHECK (subject_kind IN ('user', 'org_user', 'agent', 'consumer')),
    CONSTRAINT decision_records_verdict_known
        CHECK (verdict IN ('allowed', 'denied', 'challenged')),
    CONSTRAINT decision_records_rule_has_version
        CHECK (rule IS NULL OR policy_version IS NOT NULL)
);

ALTER TABLE decision_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows ON decision_records
    USING ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')) WITH CHECK ((tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on'));

-- Newest first, whole or narrowed to a subject, a verdict, a version or a
-- rule.
CREATE INDEX decision_records_by_decided ON decision_records (tenant_id, decided_at, id);
CREATE INDEX decision_records_of_subject
    ON decision_records (tenant_id, subject_kind, subject_id, decided_at, id);
CREATE INDEX decision_records_by_verdict
    ON decision_records (tenant_id, verdict, decided_at, id);
CREATE INDEX decision_records_by_version
    ON decision_records (tenant_id, policy_version, decided_at, id)
    WHERE policy_version IS NOT NULL;
CREATE INDEX decision_records_by_rule ON decision_records (tenant_id, rule, decided_at, id)
    WHERE rule IS NOT NULL;
