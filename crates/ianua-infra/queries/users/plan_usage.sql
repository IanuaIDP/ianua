-- What the given tenants use against their organization's plan, in one
-- database: the accounts of all of them together, and for every other kind
-- the most any one of them holds. Each kind is counted as the plan limit
-- counts it when something is made.
SELECT
    (SELECT count(*) FROM users WHERE tenant_id = ANY($1)) AS "users!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM routes
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "routes!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM registered_domains
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "domains!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM api_keys
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "api_keys!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM oauth_clients
        WHERE tenant_id = ANY($1) AND status <> 'revoked' GROUP BY tenant_id) AS counted)
        AS "oauth_clients!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM roles
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "roles!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM groups
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "groups!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM webhook_subscriptions
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "webhooks!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM federation_connections
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "federation_connections!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM consumers
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "consumers!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM services
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "services!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM stream_routes
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "stream_routes!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM egress_policies
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "egress_policies!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM resource_types
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "resource_types!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM user_attribute_definitions
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "user_attributes!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM agents
        WHERE tenant_id = ANY($1) AND status <> 'revoked' GROUP BY tenant_id) AS counted)
        AS "agents!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM agent_tools
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "agent_tools!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM agent_model_providers
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "model_providers!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM workflows
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "workflows!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM sandboxes
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "sandboxes!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM saml_service_providers
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "saml_service_providers!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM directory_service_accounts
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted)
        AS "directory_service_accounts!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM topic_subscriptions
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "message_subscriptions!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM connectors
        WHERE tenant_id = ANY($1) AND status <> 'revoked' GROUP BY tenant_id) AS counted)
        AS "connectors!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM log_shipping_targets
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "log_targets!",
    (SELECT coalesce(max(held), 0) FROM (SELECT count(*) AS held FROM audit_streams
        WHERE tenant_id = ANY($1) GROUP BY tenant_id) AS counted) AS "audit_streams!"
