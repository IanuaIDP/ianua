'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { ModelProvider, ModelProviderAction } from '@/types/model-provider';

type ModelProviderMenuAction = ModelProviderAction | 'Data clearance' | 'Embedding model';

type ModelProviderActionsMenuProps = {
  onActionConfirm: (provider: ModelProvider, action: ModelProviderAction) => Promise<void> | void;
  onClearance: (provider: ModelProvider) => void;
  onEmbeddingModel: (provider: ModelProvider) => void;
  provider: ModelProvider;
};

export function ModelProviderActionsMenu({
  onActionConfirm,
  onClearance,
  onEmbeddingModel,
  provider,
}: ModelProviderActionsMenuProps) {
  const t = useTranslations('dashboard.modelProviders');
  const tActions = useTranslations('dashboard.actions');
  const modelProviderActionModalContent: Record<ModelProviderAction, DashboardActionModalContent> =
    {
      'Enable provider': {
        title: t('actionModals.enable.title'),
        description: t('actionModals.enable.description'),
        primaryActionLabel: t('actionModals.enable.submit'),
      },
      'Disable provider': {
        title: t('actionModals.disable.title'),
        description: t('actionModals.disable.description'),
        primaryActionLabel: t('actionModals.disable.submit'),
      },
      Delete: {
        title: t('actionModals.delete.title'),
        description: t('actionModals.delete.description'),
        primaryActionLabel: t('actionModals.delete.submit'),
        warningTone: 'danger',
      },
    };
  const { hasPermission } = useTenantPermissions();
  const statusActions: ModelProviderAction[] =
    provider.status === 'Disabled' ? ['Enable provider', 'Delete'] : ['Disable provider'];
  const actions: ModelProviderMenuAction[] = !hasPermission('Agents', 'Manage')
    ? []
    : provider.kind === 'anthropic'
      ? ['Data clearance', ...statusActions]
      : ['Data clearance', 'Embedding model', ...statusActions];

  return (
    <DashboardActionsMenu<ModelProviderMenuAction>
      actionLabels={{
        'Data clearance': t('clearance.action'),
        'Embedding model': t('embeddings.action'),
      }}
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: provider.name })}
      customActions={['Data clearance', 'Embedding model']}
      onCustomAction={(action) =>
        action === 'Data clearance' ? onClearance(provider) : onEmbeddingModel(provider)
      }
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        t(
          action === 'Delete'
            ? 'toasts.deleted'
            : action === 'Enable provider'
              ? 'toasts.enabled'
              : 'toasts.disabled',
        )
      }
      modalContentByAction={modelProviderActionModalContent}
      onActionConfirm={(action) =>
        action === 'Embedding model' || action === 'Data clearance'
          ? undefined
          : onActionConfirm(provider, action)
      }
    />
  );
}
