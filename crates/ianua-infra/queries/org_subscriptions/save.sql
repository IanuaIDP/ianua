-- Keeps an organization's subscription: a new one is added, the one it
-- has takes the new values. When it started never changes.
INSERT INTO org_subscriptions
    (organization_id, plan, cycle, state, trial_ends_at, past_due_since,
     payment_reference, trial, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (organization_id) DO UPDATE SET
    plan = EXCLUDED.plan,
    cycle = EXCLUDED.cycle,
    state = EXCLUDED.state,
    trial_ends_at = EXCLUDED.trial_ends_at,
    past_due_since = EXCLUDED.past_due_since,
    payment_reference = EXCLUDED.payment_reference,
    trial = EXCLUDED.trial,
    updated_at = EXCLUDED.updated_at
