DROP INDEX scheduled_jobs_ended;

ALTER TABLE directory_service_accounts DROP CONSTRAINT directory_service_accounts_access_known;

ALTER TABLE gateway_events DROP CONSTRAINT gateway_events_event_type_raised_by_the_gateway;

ALTER TABLE scheduled_jobs DROP CONSTRAINT scheduled_jobs_status_known;

-- How the gateway closed the connection the request upgraded, when it
-- closed it for access: one of the words the gateway records, and when.
ALTER TABLE proxy_request_records ADD COLUMN closed_reason text;

ALTER TABLE proxy_request_records ADD COLUMN closed_at timestamp with time zone;

-- How long the key holds: 'live' while the job waits or runs, 'kept' for as
-- long as the row is kept, for work done once per event.
ALTER TABLE scheduled_jobs ADD COLUMN key_hold text DEFAULT 'live'::text NOT NULL;

-- Where the session was last used, as far as any use of it could be placed:
-- the network, its place and when. All are NULL until the first use that
-- can be placed; a refresh carries them on.
ALTER TABLE sessions ADD COLUMN last_used_network text;

ALTER TABLE sessions ADD COLUMN last_used_latitude double precision;

ALTER TABLE sessions ADD COLUMN last_used_longitude double precision;

ALTER TABLE sessions ADD COLUMN last_used_country text;

ALTER TABLE sessions ADD COLUMN last_used_at timestamp with time zone;

-- Service accounts only read: the directory refused every write from one
-- marked read_write, so marking them read_only takes nothing away. The
-- setting opens every tenant's rows to this transaction alone.
SET LOCAL app.platform_scope = 'on';
UPDATE directory_service_accounts SET access = 'read_only' WHERE access <> 'read_only';

ALTER TABLE directory_service_accounts ADD CONSTRAINT directory_service_accounts_access_known CHECK ((access = 'read_only'::text)) NOT VALID;
ALTER TABLE directory_service_accounts VALIDATE CONSTRAINT directory_service_accounts_access_known;

ALTER TABLE gateway_events ADD CONSTRAINT gateway_events_event_type_raised_by_the_gateway CHECK ((event_type = ANY (ARRAY['agents.action_authorized'::text, 'agents.action_denied'::text, 'agents.egress_denied'::text, 'agents.token_attack_refused'::text, 'proxy.honeypot_hit'::text, 'proxy.person_turned_away'::text, 'proxy.automated_threat_detected'::text, 'proxy.canary_token_triggered'::text, 'proxy.canary_token_leaked'::text, 'authentication.session_suspended'::text, 'authentication.session_revoked'::text]))) NOT VALID;
ALTER TABLE gateway_events VALIDATE CONSTRAINT gateway_events_event_type_raised_by_the_gateway;

ALTER TABLE proxy_request_records ADD CONSTRAINT proxy_request_records_closed_known CHECK ((closed_reason = ANY (ARRAY['access_ended'::text, 'check_failed'::text, 'credential_expired'::text]))) NOT VALID;
ALTER TABLE proxy_request_records VALIDATE CONSTRAINT proxy_request_records_closed_known;

ALTER TABLE proxy_request_records ADD CONSTRAINT proxy_request_records_closed_whole CHECK (((closed_reason IS NULL) = (closed_at IS NULL))) NOT VALID;
ALTER TABLE proxy_request_records VALIDATE CONSTRAINT proxy_request_records_closed_whole;

ALTER TABLE scheduled_jobs ADD CONSTRAINT scheduled_jobs_kept_with_key CHECK (((job_key IS NOT NULL) OR (key_hold = 'live'::text))) NOT VALID;
ALTER TABLE scheduled_jobs VALIDATE CONSTRAINT scheduled_jobs_kept_with_key;

ALTER TABLE scheduled_jobs ADD CONSTRAINT scheduled_jobs_key_hold_known CHECK ((key_hold = ANY (ARRAY['live'::text, 'kept'::text]))) NOT VALID;
ALTER TABLE scheduled_jobs VALIDATE CONSTRAINT scheduled_jobs_key_hold_known;

ALTER TABLE scheduled_jobs ADD CONSTRAINT scheduled_jobs_status_known CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'dead'::text, 'superseded'::text]))) NOT VALID;
ALTER TABLE scheduled_jobs VALIDATE CONSTRAINT scheduled_jobs_status_known;

ALTER TABLE sessions ADD CONSTRAINT sessions_last_use_whole CHECK ((num_nonnulls(last_used_network, last_used_latitude, last_used_longitude, last_used_country, last_used_at) = ANY (ARRAY[0, 5]))) NOT VALID;
ALTER TABLE sessions VALIDATE CONSTRAINT sessions_last_use_whole;
