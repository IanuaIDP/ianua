-- The bytes of the tenant's module with the given digest.
SELECT bytecode
FROM wasm_modules
WHERE tenant_id = $1 AND module_ref = $2
