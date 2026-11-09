ALTER TABLE workflow_account_channels DROP CONSTRAINT workflow_account_channels_account_id_fkey;

ALTER TABLE integration_accounts ADD CONSTRAINT integration_accounts_tenant_id_key UNIQUE (tenant_id, id);

ALTER TABLE workflow_account_channels ADD CONSTRAINT workflow_account_channels_account_fkey FOREIGN KEY (tenant_id, account_id) REFERENCES integration_accounts(tenant_id, id) ON DELETE CASCADE NOT VALID;
ALTER TABLE workflow_account_channels VALIDATE CONSTRAINT workflow_account_channels_account_fkey;
