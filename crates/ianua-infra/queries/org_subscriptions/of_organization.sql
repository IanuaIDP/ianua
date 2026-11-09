-- The subscription of one organization.
SELECT organization_id, plan, cycle, state, trial_ends_at, past_due_since,
       payment_reference, trial, created_at, updated_at
FROM org_subscriptions
WHERE organization_id = $1
