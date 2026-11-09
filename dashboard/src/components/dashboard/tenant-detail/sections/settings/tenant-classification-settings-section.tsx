'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { AddClassificationRuleModal } from '@/components/dashboard/tenant-detail/sections/settings/classification/add-classification-rule-modal';
import { ClassificationRulesTable } from '@/components/dashboard/tenant-detail/sections/settings/classification/classification-rules-table';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  addClassificationRule,
  getApiErrorMessage,
  getClassificationRules,
  removeClassificationRule,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ClassificationRuleInput } from '@/schemas/classification-schemas';
import type { ClassificationRule } from '@/types/classification';

export function TenantClassificationSettingsSection() {
  const t = useTranslations('dashboard.tenantSettings.classification');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdate = hasPermission('Classification', 'Update');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const rulesQueryKey = ['tenant-classification', orgSlug, tenantSlug];

  const {
    data: rules = [],
    error: rulesError,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getClassificationRules(orgSlug ?? '', tenantSlug),
    queryKey: rulesQueryKey,
  });

  const {
    error: addError,
    isPending: isAdding,
    mutate: submitRule,
    reset: resetAddMutation,
  } = useMutation({
    mutationFn: (payload: ClassificationRuleInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return addClassificationRule(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsAddModalOpen(false);
      showNotification({ message: t('toasts.added'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: rulesQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  async function handleRemoveRule(rule: ClassificationRule) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await removeClassificationRule(orgSlug, tenantSlug, rule.id);
    await queryClient.invalidateQueries({ queryKey: rulesQueryKey });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <SettingsCard
        title={t('title')}
        description={t('description')}
        className="overflow-hidden"
        headerAction={
          canUpdate ? (
            <Button
              type="button"
              onClick={() => {
                resetAddMutation();
                setIsAddModalOpen(true);
              }}
              className="w-auto shrink-0 bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
            >
              {t('classify')}
            </Button>
          ) : null
        }
      >
        {rulesError ? (
          <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
            {getApiErrorMessage(rulesError, t('loadFailed'))}
          </p>
        ) : null}

        <div className="-mx-4 -mb-4">
          <ClassificationRulesTable
            canUpdate={canUpdate}
            isLoading={isLoading}
            rules={rules}
            onRemoveConfirm={handleRemoveRule}
          />
        </div>
      </SettingsCard>

      <AddClassificationRuleModal
        key={isAddModalOpen ? 'add-rule-open' : 'add-rule-closed'}
        errorMessage={addError ? getApiErrorMessage(addError, t('toasts.addFailed')) : null}
        isSubmitting={isAdding}
        open={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={(payload) => submitRule(payload)}
      />
    </>
  );
}
