-- The platform's side of scheduling: the claims that run each round of a
-- sweep once across every worker, and the leases that keep one worker on
-- an agent run or a workflow execution.

-- The rounds of each sweep a worker claimed. The first claim of a round
-- wins; every later one finds it taken.
CREATE TABLE platform_sweep_claims (
    sweep text NOT NULL,
    round bigint NOT NULL,
    claimed_at timestamptz NOT NULL,
    PRIMARY KEY (sweep, round)
);

-- Old rounds are removed as new ones are claimed.
CREATE INDEX platform_sweep_claims_by_age ON platform_sweep_claims (claimed_at);

-- The worker driving each agent run and each workflow execution, until its
-- lease runs out. A lease that ran out is taken over by the next worker
-- that asks.
CREATE TABLE platform_leases (
    leased text NOT NULL,
    -- no foreign key: the run or execution lives in its tenant's database, which may be one of its own
    leased_id uuid NOT NULL,
    -- no foreign key: the holder is a worker process, kept nowhere
    holder uuid NOT NULL,
    leased_until timestamptz NOT NULL,
    PRIMARY KEY (leased, leased_id),
    CONSTRAINT platform_leases_leased_known
        CHECK (leased IN ('agent_run', 'workflow_execution'))
);
