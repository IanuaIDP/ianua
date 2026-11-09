import { useTranslations } from 'next-intl';

import {
  AUTHORIZE_CHECK_METHODS,
  AUTHORIZE_CHECK_MODES,
  DELEGATION_BUDGET_WINDOW_SECONDS,
  DELEGATION_DEPTHS,
  DELEGATION_PRESETS,
  DELEGATION_RESOURCE_RELATIONS,
  DELEGATION_TTL_SECONDS,
  type DelegationPresetId,
} from '@/constants/delegation';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SelectOption } from '@/types/dashboard';
import type { Delegation, DelegationIntent } from '@/types/delegation';

type GrantBulletsInput = {
  maxDepth: string;
  purpose?: string;
  requestLimit?: string;
  requiresApproval: boolean;
  senderConstrained: boolean;
};

/** Delegation choices and wording, in the current language. */
export function useDelegationText() {
  const t = useTranslations('dashboard.delegations');
  const tTtl = useLooseTranslations('dashboard.delegations.ttl');
  const tDepth = useLooseTranslations('dashboard.delegations.depth');
  const tWindow = useLooseTranslations('dashboard.delegations.window');
  const tRelations = useLooseTranslations('dashboard.delegations.relations');
  const tModes = useLooseTranslations('dashboard.delegations.check.modes');
  const tNouns = useLooseTranslations('dashboard.delegations.permissionNouns');
  const tVerbs = useLooseTranslations('dashboard.delegations.permissionVerbs');

  const ttlOptions: SelectOption[] = DELEGATION_TTL_SECONDS.map((seconds) => ({
    label: tTtl(seconds),
    value: seconds,
  }));
  const depthOptions: SelectOption[] = DELEGATION_DEPTHS.map((depth) => ({
    label: tDepth(depth),
    value: depth,
  }));
  const budgetWindowOptions: SelectOption[] = DELEGATION_BUDGET_WINDOW_SECONDS.map((seconds) => ({
    label: tWindow(seconds),
    value: seconds,
  }));
  const resourceRelationOptions: SelectOption[] = DELEGATION_RESOURCE_RELATIONS.map((relation) => ({
    label: tRelations(relation),
    value: relation,
  }));
  const checkModeOptions: SelectOption[] = AUTHORIZE_CHECK_MODES.map((mode) => ({
    label: tModes(mode),
    value: mode,
  }));
  const checkMethodOptions: SelectOption[] = AUTHORIZE_CHECK_METHODS.map((method) => ({
    label: method === 'Any' ? t('check.anyMethod') : method.toUpperCase(),
    value: method,
  }));
  const presets = DELEGATION_PRESETS.map((preset) => ({
    ...preset,
    description: t(`presets.${preset.id}.description`),
    label: t(`presets.${preset.id}.label`),
  }));

  /** What a `domain:action` permission lets someone do, in plain words. */
  function permissionLabel(domainAction: string): string {
    const [domain, action] = domainAction.split(':');
    const noun = tNouns.has(domain ?? '')
      ? tNouns(domain ?? '')
      : (domain ?? '').replace(/_/g, ' ');

    if (!action || !tVerbs.has(action) || !noun) {
      return domainAction;
    }

    return tVerbs(action, { noun });
  }

  function title(delegation: Delegation) {
    return (
      (delegation.name ? permissionLabel(delegation.name) : '') ||
      delegation.intent?.statement ||
      (delegation.task ? permissionLabel(delegation.task) : '') ||
      t('fallbackTitle', { id: delegation.delegationId.slice(0, 8) })
    );
  }

  function driftMode(intent: DelegationIntent | null) {
    if (!intent) {
      return '—';
    }

    if (intent.mode === 'off') {
      return t('drift.off');
    }

    const mode = intent.mode === 'enforce' ? t('drift.enforce') : t('drift.warn');

    return intent.thresholdBasisPoints != null
      ? t('drift.at', { bp: intent.thresholdBasisPoints, mode })
      : mode;
  }

  function chainLabel(delegation: Delegation) {
    const hops = t('chain.hopsLeft', { count: delegation.maxDepth });

    return delegation.depth === 0
      ? t('chain.root', { hops })
      : t('chain.depth', { depth: delegation.depth, hops });
  }

  function grantBullets(input: GrantBulletsInput): string[] {
    const { maxDepth, purpose, requestLimit, requiresApproval, senderConstrained } = input;
    const bullets: string[] = [];

    const limit = requestLimit?.trim();
    if (limit) {
      bullets.push(t('bullets.limit', { limit }));
    }

    bullets.push(
      maxDepth === '0'
        ? t('bullets.noPassing')
        : maxDepth === '1'
          ? t('bullets.passOne')
          : t('bullets.passMany', { count: maxDepth }),
    );

    if (senderConstrained) {
      bullets.push(t('bullets.sender'));
    }

    if (requiresApproval) {
      bullets.push(t('bullets.approval'));
    }

    if (purpose?.trim()) {
      bullets.push(t('bullets.purpose', { purpose: purpose.trim() }));
    }

    bullets.push(t('bullets.revocable'));

    return bullets;
  }

  return {
    budgetWindowOptions,
    chainLabel,
    checkMethodOptions,
    checkModeOptions,
    depthOptions,
    driftMode,
    grantBullets,
    permissionLabel,
    presetLabel: (id: DelegationPresetId) => t(`presets.${id}.label`),
    presets,
    resourceRelationOptions,
    title,
    ttlOptions,
  };
}
