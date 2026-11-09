'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { isAxiosError } from 'axios';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { PolicyRuleEditor } from '@/components/dashboard/tenant-detail/sections/policy/policy-rule-editor';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { useNotification } from '@/components/ui/notifications';
import { buildAction, buildCondition } from '@/constants/policy';
import { usePolicyOptions } from '@/hooks/dashboard/use-policy-options';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  changePolicyStatus,
  deriveErrorMessage,
  getApiErrorMessage,
  getPolicy,
  startPolicyDraft,
  updatePolicy,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { PolicyAction, PolicyRule, PolicyStatus, PolicyTransition } from '@/types/policy';
import { getActionKind, getDenyReason } from '@/utils/policy';
import { cn } from '@/utils/cn';

const STATUS_TONE: Record<PolicyStatus, string> = {
  Active: 'bg-success/15 text-success',
  Archived: 'bg-error/15 text-error',
  Draft: 'bg-hoverBg text-textGray',
  Review: 'bg-orange/15 text-orange',
};

type PolicyMove = {
  id: 'activate' | 'archive' | 'reject' | 'submit' | 'takeOut';
  /** The right the platform asks for this move: writing a rule is not going live. */
  needs: 'Activate' | 'Update';
  to: PolicyTransition;
};

/** Which moves make sense from where the policy currently sits. */
function availableMoves(status: PolicyStatus): PolicyMove[] {
  switch (status) {
    case 'Draft':
      return [
        { id: 'submit', needs: 'Update', to: 'submit_for_review' },
        { id: 'archive', needs: 'Update', to: 'abandon_draft' },
      ];
    case 'Review':
      return [
        { id: 'activate', needs: 'Activate', to: 'activate' },
        { id: 'reject', needs: 'Activate', to: 'reject' },
      ];
    case 'Active':
      return [{ id: 'takeOut', needs: 'Activate', to: 'take_out_of_use' }];
    default:
      return [];
  }
}

type ConfirmedMove = PolicyMove & { id: 'activate' | 'archive' | 'takeOut' };

function isConfirmedMove(option: PolicyMove): option is ConfirmedMove {
  return option.id === 'activate' || option.id === 'archive' || option.id === 'takeOut';
}

const DENY_BY_DEFAULT: PolicyAction = { Deny: { reason: 'not allowed by policy' } };

export function TenantPolicySection() {
  const t = useTranslations('dashboard.policy');
  const tStatus = useTranslations('dashboard.status');
  const tErrors = useTranslations('common.errors');
  const { actionOptions } = usePolicyOptions();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdate = hasPermission('PolicySet', 'Update');
  const [pendingMove, setPendingMove] = useState<ConfirmedMove | null>(null);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const policyQueryKey = ['tenant-policy', orgSlug, tenantSlug];

  const {
    data: policy,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getPolicy(orgSlug ?? '', tenantSlug),
    queryKey: policyQueryKey,
  });

  // Edits live in their own state and the saved policy shows through until
  // there are any. Nothing has to copy the server's answer into local state on
  // arrival, so there is no moment where the two disagree, and "unsaved" is
  // exactly "someone has touched this" rather than a flag kept in step by hand.
  const [edit, setEdit] = useState<{ defaultAction: PolicyAction; rules: PolicyRule[] } | null>(
    null,
  );

  const rules = edit?.rules ?? policy?.rules ?? [];
  const defaultAction = edit?.defaultAction ?? policy?.defaultAction ?? DENY_BY_DEFAULT;
  const isDirty = edit !== null;

  function setRules(next: PolicyRule[]) {
    setEdit({ defaultAction, rules: next });
  }

  function setDefaultAction(next: PolicyAction) {
    setEdit({ defaultAction: next, rules });
  }

  const { isPending: isStartingDraft, mutate: startDraft } = useMutation({
    mutationFn: (fallback: PolicyAction | undefined) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return startPolicyDraft(orgSlug, tenantSlug, fallback);
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.draftStarted'), type: 'success' });
      setEdit(null);
      await queryClient.invalidateQueries({ queryKey: policyQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.draftFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isSaving, mutate: save } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (!policy) {
        throw new Error(t('loadFailed'));
      }

      return updatePolicy(orgSlug, tenantSlug, policy, { defaultAction, rules });
    },
    onSuccess: async () => {
      showNotification({ message: t('toasts.saved'), type: 'success' });
      setEdit(null);
      await queryClient.invalidateQueries({ queryKey: policyQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.saveFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isMoving, mutate: move } = useMutation({
    mutationFn: (to: PolicyTransition) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return changePolicyStatus(orgSlug, tenantSlug, to);
    },
    onSuccess: async (updated) => {
      setPendingMove(null);
      showNotification({ message: t(`statusDescriptions.${updated.status}`), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: policyQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.moveFailed')),
        type: 'error',
      });
    },
  });

  const status = policy?.status ?? 'Draft';
  const isEditable = policy?.editable ?? false;
  const isBusy = isLoading || isSaving || isMoving || !isEditable || !canUpdate;
  const moves = policy ? availableMoves(status) : [];
  const hasRestrictedMove = moves.some((option) => !hasPermission('PolicySet', option.needs));

  function startMove(option: PolicyMove) {
    if (isConfirmedMove(option)) {
      setPendingMove(option);
      return;
    }

    move(option.to);
  }
  const defaultActionKind = getActionKind(defaultAction);

  function updateRule(index: number, next: PolicyRule) {
    setRules(rules.map((rule, i) => (i === index ? next : rule)));
  }

  const isPolicyMissing = isAxiosError(error) && error.response?.status === 404;
  const errorMessage = deriveErrorMessage([
    error && !isPolicyMissing,
    getApiErrorMessage(error, t('loadFailed')),
  ]);

  return (
    <div className="mx-auto flex w-full max-w-360 flex-col gap-4">
      <SettingsCard
        title={t('standing.title')}
        description={t(`statusDescriptions.${status}`)}
        headerAction={
          <span
            className={cn(
              'inline-flex h-6 items-center rounded-full px-3 text-xs font-semibold',
              STATUS_TONE[status],
            )}
          >
            {tStatus(status)}
          </span>
        }
      >
        {status === 'Active' ? (
          <p className="mb-4 rounded-md border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange">
            {t('standing.live')}
          </p>
        ) : null}

        {policy ? (
          <p className="mb-4 text-xs font-medium text-textGray">
            {t('standing.version', { version: policy.version })}
            {policy.basedOnVersion !== null
              ? ` · ${t('standing.basedOn', { version: policy.basedOnVersion })}`
              : ''}
          </p>
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          {moves.map((option) => (
            <Button
              key={option.to}
              type="button"
              variant="outline"
              disabled={isMoving || isLoading || !hasPermission('PolicySet', option.needs)}
              onClick={() => startMove(option)}
              className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 text-xs font-medium text-white hover:bg-hoverBg"
            >
              {t(`moves.${option.id}`)}
            </Button>
          ))}
          {policy?.status === 'Active' || isPolicyMissing ? (
            <Button
              type="button"
              variant="outline"
              disabled={isStartingDraft || isLoading || !canUpdate}
              onClick={() => startDraft(isPolicyMissing ? DENY_BY_DEFAULT : undefined)}
              className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 text-xs font-medium text-white hover:bg-hoverBg"
            >
              {t('moves.startDraft')}
            </Button>
          ) : null}
          {policy && moves.length === 0 ? (
            <p className="text-xs font-medium text-textGray">{t('standing.archived')}</p>
          ) : null}
          {hasRestrictedMove ? (
            <p className="text-xs font-medium text-textGray">{t('standing.noActivate')}</p>
          ) : null}
        </div>
      </SettingsCard>

      <SettingsCard title={t('rules.title')} description={t('rules.description')}>
        <div className="flex flex-col gap-4">
          {rules.map((rule, index) => (
            <PolicyRuleEditor
              key={index}
              isBusy={isBusy}
              rule={rule}
              onChange={(next) => updateRule(index, next)}
              onRemove={() => setRules(rules.filter((_, i) => i !== index))}
            />
          ))}

          {policy && rules.length === 0 ? (
            <p className="rounded-lg border border-dashed border-borderGray px-4 py-6 text-center text-xs font-medium text-textGray">
              {t('rules.empty')}
            </p>
          ) : null}

          <div>
            <Button
              type="button"
              variant="outline"
              disabled={isBusy}
              onClick={() => {
                setRules([
                  ...rules,
                  {
                    action: 'Allow',
                    conditions: [buildCondition('PathPrefix', '')],
                    enabled: true,
                    name: '',
                    priority: (rules.length + 1) * 10,
                  },
                ]);
              }}
              className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 text-xs font-medium text-white hover:bg-hoverBg"
            >
              {t('rules.add')}
            </Button>
          </div>
        </div>
      </SettingsCard>

      <SettingsCard title={t('fallback.title')} description={t('fallback.description')}>
        <div className="grid gap-4 sm:grid-cols-2 sm:items-start">
          <Select
            label={t('fallback.label')}
            containerClassName="mb-0"
            className="bg-appBg"
            hint={t('fallback.hint')}
            options={actionOptions}
            value={defaultActionKind}
            disabled={isBusy}
            onChange={(next) =>
              setDefaultAction(buildAction(next, getDenyReason(defaultAction), 'Aal2'))
            }
          />

          {defaultActionKind === 'Deny' ? (
            <Input
              label={t('reason')}
              placeholder={t('reasonPlaceholder')}
              containerClassName="mb-0"
              className="bg-appBg"
              value={getDenyReason(defaultAction)}
              disabled={isBusy}
              onChange={(event) =>
                setDefaultAction(buildAction('Deny', event.target.value, 'Aal2'))
              }
            />
          ) : null}
        </div>
      </SettingsCard>

      {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}

      <div className="flex items-center gap-4">
        <Button
          type="button"
          isLoading={isSaving}
          disabled={isBusy || !isDirty}
          onClick={() => save()}
          className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
        >
          {t('save')}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={isSaving || !isDirty}
          onClick={() => setEdit(null)}
          className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
        >
          {t('discard')}
        </Button>
      </div>

      <Modal
        open={Boolean(pendingMove)}
        onClose={() => {
          if (!isMoving) {
            setPendingMove(null);
          }
        }}
        title={pendingMove ? t(`moveConfirm.${pendingMove.id}.title`) : undefined}
        description={pendingMove ? t(`moveConfirm.${pendingMove.id}.description`) : undefined}
        showCloseButton={false}
        primaryActionLabel={pendingMove ? t(`moves.${pendingMove.id}`) : undefined}
        onPrimaryAction={() => {
          if (pendingMove) {
            move(pendingMove.to);
          }
        }}
        isPrimaryActionLoading={isMoving}
        isPrimaryActionDisabled={isMoving}
      >
        {isDirty ? (
          <p className="text-xs font-medium text-orange">{t('moveConfirm.unsaved')}</p>
        ) : null}
      </Modal>
    </div>
  );
}
