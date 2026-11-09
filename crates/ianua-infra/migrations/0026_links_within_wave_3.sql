-- Links between the third wave's tables, made once both sides exist.

-- A run acts under its delegation, which goes only with its agent, as the
-- run does.
ALTER TABLE agent_runs
    ADD CONSTRAINT agent_runs_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE;
CREATE INDEX agent_runs_under_delegation ON agent_runs (tenant_id, delegation_id);

-- An approval asked under a delegation means nothing once it is gone.
ALTER TABLE agent_approvals
    ADD CONSTRAINT agent_approvals_delegation_fkey FOREIGN KEY (tenant_id, delegation_id)
        REFERENCES agent_delegations (tenant_id, id) ON DELETE CASCADE;

-- A workflow run waits on an agent run only while it stands; a deleted
-- agent takes its runs, and the stalled-work sweep ends the waiting run.
ALTER TABLE workflow_execution_runs
    ADD CONSTRAINT workflow_execution_runs_agent_run_fkey FOREIGN KEY (tenant_id, agent_run_id)
        REFERENCES agent_runs (tenant_id, id) ON DELETE CASCADE;
