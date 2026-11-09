-- Keeps a model provider: a new one is added, a known one of the same
-- tenant takes the new values. Its tenant, its kind and its creation time
-- never change.
INSERT INTO agent_model_providers
    (id, tenant_id, name, kind, endpoint, model, input_price_micros, output_price_micros,
     api_key_sealed, clearance, status, last_test_status, last_tested_at, last_test_reason,
     created_at, updated_at, embedding_model)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    endpoint = EXCLUDED.endpoint,
    model = EXCLUDED.model,
    embedding_model = EXCLUDED.embedding_model,
    input_price_micros = EXCLUDED.input_price_micros,
    output_price_micros = EXCLUDED.output_price_micros,
    api_key_sealed = EXCLUDED.api_key_sealed,
    clearance = EXCLUDED.clearance,
    status = EXCLUDED.status,
    last_test_status = EXCLUDED.last_test_status,
    last_tested_at = EXCLUDED.last_tested_at,
    last_test_reason = EXCLUDED.last_test_reason,
    updated_at = EXCLUDED.updated_at
WHERE agent_model_providers.tenant_id = EXCLUDED.tenant_id
