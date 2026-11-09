-- Keeps how jobs ended, each while it is still running at the attempt it
-- was claimed at; a job another worker took since is left alone. Each is
-- matched on its tenant as well as its id.
UPDATE scheduled_jobs AS j
SET status = ended.status, run_at = ended.run_at, error = ended.error, leased_until = NULL
FROM unnest($1::uuid[], $2::uuid[], $3::integer[], $4::text[], $5::timestamptz[], $6::text[])
    AS ended (id, tenant_id, attempt, status, run_at, error)
WHERE j.id = ended.id AND j.tenant_id IS NOT DISTINCT FROM ended.tenant_id
  AND j.status = 'running' AND j.attempt = ended.attempt
