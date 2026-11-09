import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getTeamMembers } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type {
  TenantAgent,
  TenantAgentAction,
  TenantAgentOwner,
  TenantAgentOwnerDisplay,
} from '@/types/tenant-agent';
import type { TenantUser } from '@/types/tenant-user';
import { getInitials } from '@/utils/initials';
import { shortId } from '@/utils/tenant-agent';

/** Wording that depends on an agent, in the current language. */
export function useAgentText() {
  const t = useTranslations('dashboard.agents');
  const { orgSlug } = useTenantRouteParams();
  const isOrganizationSession = useAuthStore((state) => state.access !== null);
  const { data: team } = useQuery({
    enabled: isOrganizationSession && Boolean(orgSlug),
    queryFn: () => getTeamMembers(orgSlug ?? '', { limit: 100 }),
    queryKey: ['team-members', orgSlug, 'owner-lookup'],
    retry: false,
  });

  function reattestInterval(seconds: number | null): string {
    if (!seconds || seconds <= 0) {
      return t('notConfigured');
    }

    if (seconds % 3600 === 0) {
      return t('interval.hours', { count: seconds / 3600 });
    }

    if (seconds % 60 === 0) {
      return t('interval.minutes', { count: seconds / 60 });
    }

    return t('interval.seconds', { count: seconds });
  }

  function ownerDisplay(
    owner: TenantAgentOwner,
    usersById: Map<string, TenantUser>,
    agentsById: Map<string, TenantAgent>,
  ): TenantAgentOwnerDisplay {
    if (owner.kind === 'user') {
      const user = usersById.get(owner.id);

      if (user) {
        return {
          initial: user.avatarInitial,
          name: user.displayName,
          secondary: user.email,
          seed: user.email,
        };
      }
    }

    if (owner.kind === 'org_user') {
      const member = team?.items.find((candidate) => String(candidate.id) === owner.id);

      if (member) {
        return {
          initial: member.avatarInitial,
          name: member.name,
          secondary: member.email,
          seed: member.email,
        };
      }
    }

    if (owner.kind === 'agent') {
      const ownerAgent = agentsById.get(owner.id);

      if (ownerAgent) {
        return {
          initial: getInitials(ownerAgent.name),
          name: ownerAgent.name,
          secondary: t('owner.agent'),
          seed: ownerAgent.id,
        };
      }
    }

    const fallbackName = owner.kind === 'org_user' ? t('owner.orgUser') : t('owner.agent');

    return {
      initial: fallbackName.slice(0, 2).toUpperCase(),
      name: fallbackName,
      secondary: shortId(owner.id),
      seed: owner.id,
    };
  }

  function actionModalContent(
    agent: TenantAgent,
  ): Partial<Record<TenantAgentAction, DashboardActionModalContent>> {
    const values = { name: agent.name };

    return {
      Suspend: {
        title: t('actionModals.Suspend.title', values),
        description: t('actionModals.Suspend.description'),
        primaryActionLabel: t('actionModals.Suspend.submit'),
        warningNote: t('actionModals.Suspend.warning'),
      },
      Resume: {
        title: t('actionModals.Resume.title', values),
        description: t('actionModals.Resume.description'),
        primaryActionLabel: t('actionModals.Resume.submit'),
      },
      RequireReattestation: {
        title: t('actionModals.RequireReattestation.title', values),
        description: t('actionModals.RequireReattestation.description'),
        primaryActionLabel: t('actionModals.RequireReattestation.submit'),
        warningNote: t('actionModals.RequireReattestation.warning'),
      },
      Delete: {
        title: t('actionModals.Delete.title', values),
        description: t('actionModals.Delete.description'),
        primaryActionLabel: t('actionModals.Delete.submit'),
        confirmationPlaceholder: agent.name,
        confirmationValue: agent.name,
        warningNote: t('actionModals.Delete.warning'),
      },
      Contain: {
        title: t('actionModals.Contain.title', values),
        description: t('actionModals.Contain.description'),
        primaryActionLabel: t('actionModals.Contain.submit'),
        confirmationPlaceholder: agent.name,
        confirmationValue: agent.name,
        warningNote: t('actionModals.Contain.warning'),
        warningTone: 'danger',
      },
      Revoke: {
        title: t('actionModals.Revoke.title', values),
        description: t('actionModals.Revoke.description'),
        primaryActionLabel: t('actionModals.Revoke.submit'),
        confirmationPlaceholder: agent.name,
        confirmationValue: agent.name,
        warningNote: t('actionModals.Revoke.warning'),
        warningTone: 'danger',
      },
    };
  }

  return { actionModalContent, ownerDisplay, reattestInterval };
}
