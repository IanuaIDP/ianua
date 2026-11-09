-- Keeps what a look or the sweep changed in an evaluation, only while the
-- stored one is still as it was read, last changed at $6, so two that raced
-- never undo each other's step.
UPDATE evaluations
SET outcomes = $3, state = $4, updated_at = $5
WHERE tenant_id = $1 AND id = $2 AND updated_at = $6
