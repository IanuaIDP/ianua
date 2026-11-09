-- The model providers of a tenant with the given ids.
SELECT id, name, kind, endpoint, model, embedding_model, input_price_micros, output_price_micros,
       api_key_sealed, clearance, status, last_test_status, last_tested_at, last_test_reason,
       created_at, updated_at
FROM agent_model_providers
WHERE tenant_id = $1 AND id = ANY($2)
