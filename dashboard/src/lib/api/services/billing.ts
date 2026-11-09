import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';

export type BillingPlan = 'Free' | 'Starter' | 'Business' | 'Custom' | 'SelfHosted';
export type BillingCycle = 'monthly' | 'annual';

export type OrganizationSubscription = {
  cycle: BillingCycle;
  hasPaymentMethod: boolean;
  pastDueSince: string | null;
  plan: BillingPlan;
  state: 'active' | 'past_due' | 'trialing';
  trialEndsAt: string | null;
};

export type PlanChoice = {
  displayName: string;
  plan: BillingPlan;
};

type SubscriptionResponse = {
  cycle: BillingCycle;
  past_due_since?: string | null;
  payment_method_on_file: boolean;
  plan: BillingPlan;
  state: OrganizationSubscription['state'];
  trial_ends_at?: string | null;
};

type PlanCatalogResponse = {
  plans: { call_to_action: 'contact_sales' | 'sign_up'; display_name: string; plan: BillingPlan }[];
};

function getSubscriptionEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/subscription`;
}

export async function getOrganizationSubscription(
  orgSlug: string,
): Promise<OrganizationSubscription> {
  const data = await getList<SubscriptionResponse>(getSubscriptionEndpoint(orgSlug));

  return {
    cycle: data.cycle,
    hasPaymentMethod: data.payment_method_on_file,
    pastDueSince: data.past_due_since ?? null,
    plan: data.plan,
    state: data.state,
    trialEndsAt: data.trial_ends_at ?? null,
  };
}

/** The plans a person can pick themselves; a negotiated plan goes through sales. */
export async function getPlanChoices(): Promise<PlanChoice[]> {
  const data = await getList<PlanCatalogResponse>('/v1/plans');

  return data.plans
    .filter((plan) => plan.call_to_action === 'sign_up')
    .map((plan) => ({ displayName: plan.display_name, plan: plan.plan }));
}

export async function chooseOrganizationPlan(
  orgSlug: string,
  plan: BillingPlan,
  cycle: BillingCycle,
) {
  await apiClient.put(getSubscriptionEndpoint(orgSlug), { cycle, plan });
}

/** Asks where to add a payment method; the answer is the payment provider's page. */
export async function startOrganizationCheckout(orgSlug: string) {
  const response = await apiClient.post<{ checkout_url: string }>(
    `${getSubscriptionEndpoint(orgSlug)}/checkout`,
  );

  return response.data.checkout_url;
}
