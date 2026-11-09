ALTER TABLE workflow_executions DROP CONSTRAINT workflow_executions_cause_known;

ALTER TABLE workflow_versions DROP CONSTRAINT workflow_versions_trigger_known;

ALTER TABLE workflow_versions DROP CONSTRAINT workflow_versions_trigger_whole;

-- The change a "before" run decides, or NULL for any other cause.
ALTER TABLE workflow_executions ADD COLUMN cause_change text;

-- The change a "before" version decides, or NULL for any other trigger.
ALTER TABLE workflow_versions ADD COLUMN trigger_change text;

ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_before_whole CHECK (((cause = 'before'::text) = (cause_change IS NOT NULL))) NOT VALID;
ALTER TABLE workflow_executions VALIDATE CONSTRAINT workflow_executions_before_whole;

ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_cause_known CHECK ((cause = ANY (ARRAY['manual'::text, 'schedule'::text, 'webhook'::text, 'event'::text, 'service'::text, 'restart'::text, 'before'::text]))) NOT VALID;
ALTER TABLE workflow_executions VALIDATE CONSTRAINT workflow_executions_cause_known;

ALTER TABLE workflow_versions ADD CONSTRAINT workflow_versions_trigger_change_known CHECK ((trigger_change = ANY (ARRAY['access_given'::text, 'admin_given'::text, 'app_opened_to_workflows'::text, 'audit_exported'::text]))) NOT VALID;
ALTER TABLE workflow_versions VALIDATE CONSTRAINT workflow_versions_trigger_change_known;

ALTER TABLE workflow_versions ADD CONSTRAINT workflow_versions_trigger_known CHECK ((trigger_kind = ANY (ARRAY['manual'::text, 'schedule'::text, 'webhook'::text, 'event'::text, 'service'::text, 'before'::text]))) NOT VALID;
ALTER TABLE workflow_versions VALIDATE CONSTRAINT workflow_versions_trigger_known;

ALTER TABLE workflow_versions ADD CONSTRAINT workflow_versions_trigger_whole CHECK ((((trigger_kind = 'schedule'::text) = (trigger_schedule IS NOT NULL)) AND ((trigger_kind = 'event'::text) = (trigger_event IS NOT NULL)) AND ((trigger_kind = 'service'::text) = (trigger_service IS NOT NULL)) AND ((trigger_kind = 'before'::text) = (trigger_change IS NOT NULL)))) NOT VALID;
ALTER TABLE workflow_versions VALIDATE CONSTRAINT workflow_versions_trigger_whole;
