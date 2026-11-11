-- Tells the workers listening on the job channel that a job is due, once
-- the change that queued it commits; a change rolled back tells nobody.
SELECT pg_notify('ianua_jobs', '')
