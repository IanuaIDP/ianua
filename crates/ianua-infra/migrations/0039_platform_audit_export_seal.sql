-- The SHA-256 of the written file, taken as the worker wrote it.
ALTER TABLE audit_exports ADD COLUMN file_sha256 bytea;

-- The compact JWS over a ready tenant export's file, signed with the
-- tenant's signing key for an auditor to check.
ALTER TABLE audit_exports ADD COLUMN seal text;

ALTER TABLE audit_exports ADD CONSTRAINT audit_exports_digest_is_sha256 CHECK ((octet_length(file_sha256) = 32)) NOT VALID;
ALTER TABLE audit_exports VALIDATE CONSTRAINT audit_exports_digest_is_sha256;

ALTER TABLE audit_exports ADD CONSTRAINT audit_exports_digest_while_ready CHECK (((file_sha256 IS NOT NULL) = (status = 'ready'::text))) NOT VALID;
ALTER TABLE audit_exports VALIDATE CONSTRAINT audit_exports_digest_while_ready;

ALTER TABLE audit_exports ADD CONSTRAINT audit_exports_seal_on_ready_tenant_exports CHECK (((seal IS NOT NULL) = ((status = 'ready'::text) AND (log = 'tenant'::text)))) NOT VALID;
ALTER TABLE audit_exports VALIDATE CONSTRAINT audit_exports_seal_on_ready_tenant_exports;
