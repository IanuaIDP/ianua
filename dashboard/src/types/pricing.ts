export type IsolationLevel =
  'Shared' | 'DedicatedSchema' | 'DedicatedInstance' | 'DedicatedCluster';

export type PlanTier = 'Free' | 'Starter' | 'Business' | 'Custom';

export type PlanCallToAction = 'sign_up' | 'contact_sales';

export type PlanLimits = {
  max_users: number;
  max_tenants_per_org: number;
  max_routes: number;
  max_dns_record_sets: number;
  max_domains: number;
  max_proxy_requests_per_month: number;
  max_api_keys: number;
  max_oauth_clients: number;
  max_roles: number;
  max_groups: number;
  max_webhooks: number;
  max_federation_connections: number;
  max_services: number;
  max_agents: number;
  max_agent_tools: number;
  max_model_providers: number;
  max_agent_flows: number;
  max_active_agent_runs: number;
  max_pending_approvals: number;
  audit_retention_days: number;
  api_rate_limit_per_minute: number;
  allowed_isolation: IsolationLevel[];
};

export type PlanPriceResponse = {
  monthly_cents: number;
  annual_cents: number;
};

export type PlanTierResponse = {
  plan: PlanTier;
  display_name: string;
  tagline: string;
  badge?: string | null;
  highlighted: boolean;
  call_to_action: PlanCallToAction;
  price?: PlanPriceResponse | null;
  limits: PlanLimits;
};

export type PlanCatalogResponse = {
  currency: string;
  plans: PlanTierResponse[];
};

/**
 * The translator for `landing.pricing`, created on the server with
 * `getTranslations('landing.pricing')` and passed into the pricing service.
 */
export type PricingTranslator = Awaited<
  ReturnType<typeof import('next-intl/server').getTranslations<'landing.pricing'>>
>;
