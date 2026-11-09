-- Keeps a person's order to stop a run of a tenant. A later order for the
-- same run takes the place of the earlier one.
INSERT INTO agent_run_cancellations
    (tenant_id, run_id, ordered_by_kind, ordered_by_id, ordered_by_person, ordered_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, run_id) DO UPDATE SET
    ordered_by_kind = EXCLUDED.ordered_by_kind,
    ordered_by_id = EXCLUDED.ordered_by_id,
    ordered_by_person = EXCLUDED.ordered_by_person,
    ordered_at = EXCLUDED.ordered_at
