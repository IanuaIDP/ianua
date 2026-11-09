'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { useNotification } from '@/components/ui/notifications';
import {
  getApiErrorMessage,
  getGrantableRoles,
  getMemberTenantRoles,
  getTenants,
  setMemberTenantRoles,
} from '@/lib/api';
import type { MemberTenantRoles } from '@/lib/api/services/team';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TeamMember } from '@/types/team';
import type { Tenant } from '@/types/tenant';
import { cn } from '@/utils/cn';

type MemberTenantAccessModalProps = {
  member: TeamMember | null;
  onClose: () => void;
  orgSlug: string;
};

export function MemberTenantAccessModal({
  member,
  onClose,
  orgSlug,
}: MemberTenantAccessModalProps) {
  const { data: tenants = [] } = useQuery({
    enabled: Boolean(member),
    queryFn: async () =>
      (await getTenants(orgSlug, { limit: 100 })).items.filter(
        (tenant) => tenant.status !== 'Archived',
      ),
    queryKey: ['tenants', orgSlug, 'access-options'],
  });
  const { data: granted, error: grantedError } = useQuery({
    enabled: Boolean(member),
    queryFn: () => getMemberTenantRoles(orgSlug, member?.id ?? ''),
    queryKey: ['member-tenant-roles', orgSlug, member?.id],
  });

  if (!member) {
    return null;
  }

  if (!granted) {
    return <AccessFormLoading error={grantedError} member={member} onClose={onClose} />;
  }

  return (
    <AccessForm
      key={String(member.id)}
      granted={granted}
      member={member}
      onClose={onClose}
      orgSlug={orgSlug}
      tenants={tenants}
    />
  );
}

function AccessFormLoading({
  error,
  member,
  onClose,
}: {
  error: unknown;
  member: TeamMember;
  onClose: () => void;
}) {
  const t = useTranslations('dashboard.tenantAccess');

  return (
    <Modal open onClose={onClose} size="xl" title={t('title', { name: member.name })}>
      <p
        className={cn(
          'py-6 text-center text-xs font-medium',
          error ? 'text-error' : 'text-textGray',
        )}
      >
        {error ? getApiErrorMessage(error, t('loadFailed')) : t('loading')}
      </p>
    </Modal>
  );
}

type AccessFormProps = {
  granted: MemberTenantRoles;
  member: TeamMember;
  onClose: () => void;
  orgSlug: string;
  tenants: Tenant[];
};

function AccessForm({ granted, member, onClose, orgSlug, tenants }: AccessFormProps) {
  const t = useTranslations('dashboard.tenantAccess');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [selected, setSelected] = useState<MemberTenantRoles>(granted);
  const changed = tenants.filter(
    (tenant) => !sameRoles(selected[tenant.slug] ?? [], granted[tenant.slug] ?? []),
  );

  const { isPending, mutate: save } = useMutation({
    mutationFn: async () => {
      const refused: string[] = [];

      for (const tenant of changed) {
        try {
          await setMemberTenantRoles(orgSlug, member.id, tenant.slug, selected[tenant.slug] ?? []);
        } catch {
          refused.push(tenant.name);
        }
      }

      return refused;
    },
    onSuccess: async (refused) => {
      await queryClient.invalidateQueries({
        queryKey: ['member-tenant-roles', orgSlug, member.id],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);

      if (refused.length > 0) {
        showNotification({
          message: t('savedInPart', { tenants: refused.join(', ') }),
          type: 'error',
        });
        return;
      }

      showNotification({ message: t('saved', { name: member.name }), type: 'success' });
      onClose();
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('saveFailed')),
        type: 'error',
      });
    },
  });

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={t('title', { name: member.name })}
      description={t('description')}
      primaryActionLabel={t('save')}
      onPrimaryAction={() => save()}
      isPrimaryActionDisabled={changed.length === 0 || isPending}
      isPrimaryActionLoading={isPending}
    >
      <div className="flex flex-col gap-4">
        {tenants.map((tenant) => (
          <TenantRolesField
            key={tenant.slug}
            orgSlug={orgSlug}
            tenant={tenant}
            value={selected[tenant.slug] ?? []}
            onChange={(roles) => setSelected((current) => ({ ...current, [tenant.slug]: roles }))}
          />
        ))}
      </div>
    </Modal>
  );
}

type TenantRolesFieldProps = {
  onChange: (roles: string[]) => void;
  orgSlug: string;
  tenant: Tenant;
  value: string[];
};

function TenantRolesField({ onChange, orgSlug, tenant, value }: TenantRolesFieldProps) {
  const t = useTranslations('dashboard.tenantAccess');
  const { data: roles = [] } = useQuery({
    queryFn: () => getGrantableRoles(orgSlug, tenant.slug),
    queryKey: ['grantable-roles', orgSlug, tenant.slug],
  });

  return (
    <MultiSelect
      label={tenant.name}
      placeholder={t('noAccess')}
      options={roles.map((role) => ({ label: role, value: role }))}
      value={value}
      onChange={onChange}
    />
  );
}

function sameRoles(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((role) => b.includes(role));
}
