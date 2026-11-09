'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';

type AgentNextStepCardProps = {
  agentId: string;
  hasCredential: boolean;
  hasDelegation: boolean;
  tenantSlug: string;
};

type Step = {
  description: string;
  done: boolean;
  href: string;
  label: string;
  title: string;
};

/// What to do next, on a page that otherwise opens on six empty tabs.
///
/// A new agent is inert: it can reach nothing and cannot authenticate. Both
/// facts are fixable in one click each, and neither is discoverable from a row
/// of tab names. This says which one is next and stops appearing once it is.
export function AgentNextStepCard({
  agentId,
  hasCredential,
  hasDelegation,
  tenantSlug,
}: AgentNextStepCardProps) {
  const t = useTranslations('dashboard.agents.nextStep');
  const { isTenantView, orgSlug } = useTenantRouteParams();
  const base =
    isTenantView && orgSlug
      ? getAgentPath(orgSlug, tenantSlug, agentId)
      : getAgentManagementPath(tenantSlug, agentId);

  // New agents are given a key as they are created, so for them this is one
  // step. The key step still appears for agents made before that was true, and
  // comes first: the default guardrails bind a grant to the agent's key, so
  // granting without one fails.
  const steps: Step[] = [
    {
      description: t('identity.description'),
      done: hasCredential,
      href: `${base}/credentials`,
      label: t('identity.action'),
      title: t('identity.title'),
    },
    {
      description: t('access.description'),
      done: hasDelegation,
      href: `${base}/delegations`,
      label: t('access.action'),
      title: t('access.title'),
    },
  ];

  const next = steps.find((step) => !step.done);

  if (!next) {
    return null;
  }

  const remaining = steps.filter((step) => !step.done).length;

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-primary/40 bg-primary/5 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-start gap-3">
        <span className="material-symbols-rounded text-base! text-primary" aria-hidden>
          rocket_launch
        </span>
        <div className="flex flex-col gap-0.5">
          <p className="text-xs font-semibold text-white">
            {next.title}
            <span className="ml-2 font-normal text-textGray">
              {t('remaining', { count: remaining })}
            </span>
          </p>
          <p className="text-xs leading-snug text-textGray">{next.description}</p>
        </div>
      </div>
      <Link
        href={next.href}
        className="shrink-0 self-start rounded-md bg-primary px-3 py-1.5 text-xs font-semibold text-black transition hover:bg-btnWithBgHover sm:self-auto"
      >
        {next.label}
      </Link>
    </div>
  );
}
