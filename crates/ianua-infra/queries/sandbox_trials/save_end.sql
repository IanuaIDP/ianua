-- Keeps how a trial went, only while the stored trial still runs, so a
-- second try that raced the first changes nothing.
UPDATE sandbox_trials
SET state = $3, output = $4, failure = $5, failure_detail = $6, updated_at = $7
WHERE tenant_id = $1 AND id = $2 AND state = 'running'
