'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { getApiErrorMessage, getTenantRoles, updateTenantScimSettings } from '@/lib/api';
import type { ScimSettings } from '@/lib/api/services/connections';
import { invalidateAuditLogQueries } from '@/lib/query-keys';

const NO_ROLE = '';

type ScimSettingsFormProps = {
  canConfigure: boolean;
  initialSettings: ScimSettings;
  orgSlug: string;
  statusQueryKey: unknown[];
  tenantSlug: string;
};

export function ScimSettingsForm({
  canConfigure,
  initialSettings,
  orgSlug,
  statusQueryKey,
  tenantSlug,
}: ScimSettingsFormProps) {
  const t = useTranslations('dashboard.connections.scim.settings');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [settings, setSettings] = useState<ScimSettings>(initialSettings);

  const { data: roles = [] } = useQuery({
    queryFn: async () => (await getTenantRoles(orgSlug, tenantSlug, { limit: 100 })).items,
    queryKey: ['tenant-roles', orgSlug, tenantSlug, 'options'],
  });
  const roleOptions = [
    { label: t('noRole'), value: NO_ROLE },
    ...roles.map((role) => ({ label: role.name, value: role.id })),
  ];

  const { isPending, mutate: save } = useMutation({
    mutationFn: () => updateTenantScimSettings(orgSlug, tenantSlug, settings),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: statusQueryKey });
      showNotification({ message: t('saved'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('saveFailed')),
        type: 'error',
      });
    },
  });

  return (
    <div className="flex flex-col gap-4">
      <Select
        label={t('defaultRole')}
        hint={t('defaultRoleHint')}
        disabled={!canConfigure}
        options={roleOptions}
        value={settings.defaultRoleId ?? NO_ROLE}
        onChange={(value) =>
          setSettings((current) => ({
            ...current,
            defaultRoleId: value === NO_ROLE ? null : value,
          }))
        }
      />
      <Switch
        checked={settings.autoActivate}
        disabled={!canConfigure}
        label={t('autoActivate')}
        description={t('autoActivateHint')}
        onCheckedChange={(autoActivate) => setSettings((current) => ({ ...current, autoActivate }))}
      />
      <Switch
        checked={settings.deactivateOnRemove}
        disabled={!canConfigure}
        label={t('deactivate')}
        description={t('deactivateHint')}
        onCheckedChange={(deactivateOnRemove) =>
          setSettings((current) => ({ ...current, deactivateOnRemove }))
        }
      />
      <Button
        type="button"
        disabled={!canConfigure}
        isLoading={isPending}
        onClick={() => save()}
        className="w-auto self-start bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple"
      >
        {t('save')}
      </Button>
    </div>
  );
}
