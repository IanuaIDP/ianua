-- The subscriptions a payment is owed on, across every organization, the
-- longest owed first.
SELECT organization_id, plan, cycle, state, trial_ends_at, past_due_since,
       payment_reference, trial, created_at, updated_at
FROM org_subscriptions
WHERE state = 'past_due'
ORDER BY past_due_since, organization_id
