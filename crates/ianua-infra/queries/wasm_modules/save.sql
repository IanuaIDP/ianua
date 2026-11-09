-- Keeps an uploaded module under its digest. The same bytes uploaded
-- again keep the row already there.
INSERT INTO wasm_modules (tenant_id, module_ref, bytecode, uploaded_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, module_ref) DO NOTHING
