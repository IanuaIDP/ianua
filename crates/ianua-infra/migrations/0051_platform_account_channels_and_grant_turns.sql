ALTER TABLE platform_leases DROP CONSTRAINT platform_leases_leased_known;

ALTER TABLE platform_leases ADD CONSTRAINT platform_leases_leased_known CHECK ((leased = ANY (ARRAY['agent_run'::text, 'workflow_execution'::text, 'account_grant'::text]))) NOT VALID;
ALTER TABLE platform_leases VALIDATE CONSTRAINT platform_leases_leased_known;
