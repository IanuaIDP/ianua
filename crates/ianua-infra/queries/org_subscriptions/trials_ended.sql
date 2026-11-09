-- The subscriptions still trialing whose trial ended at or before the
-- given time, across every organization, the longest ended first.
SELECT organization_id, plan, cycle, state, trial_ends_at, past_due_since,
       payment_reference, trial, created_at, updated_at
FROM org_subscriptions
WHERE state = 'trialing' AND trial_ends_at <= $1
ORDER BY trial_ends_at, organization_id
