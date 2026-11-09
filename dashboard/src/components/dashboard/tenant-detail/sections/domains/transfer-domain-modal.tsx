'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { getTenants } from '@/lib/api';
import type { Domain } from '@/types/domain';

type TransferDomainModalProps = {
  currentTenantSlug: string;
  domain: Domain | null;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (targetTenantId: string) => void;
  open: boolean;
  orgSlug?: string;
};

export function TransferDomainModal({
  currentTenantSlug,
  domain,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
}: TransferDomainModalProps) {
  const t = useTranslations('dashboard.domains.transfer');
  const [targetTenantId, setTargetTenantId] = useState('');
  const [wasOpen, setWasOpen] = useState(open);

  if (open !== wasOpen) {
    setWasOpen(open);

    if (!open) {
      setTargetTenantId('');
    }
  }

  const { data: tenantsList, isLoading } = useQuery({
    enabled: open && Boolean(orgSlug),
    queryFn: () => getTenants(orgSlug ?? '', { limit: 100 }),
    queryKey: ['org-tenants-for-transfer', orgSlug],
  });

  const tenantOptions = (tenantsList?.items ?? [])
    .filter((tenant) => tenant.slug !== currentTenantSlug)
    .map((tenant) => ({ label: `${tenant.name} (${tenant.slug})`, value: String(tenant.id) }));

  function handleSubmit() {
    if (!targetTenantId) {
      return;
    }

    onSubmit(targetTenantId);
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={domain ? t('description', { domain: domain.domain }) : undefined}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      onPrimaryAction={handleSubmit}
      isPrimaryActionDisabled={isSubmitting || !targetTenantId}
      isPrimaryActionLoading={isSubmitting}
    >
      <Select
        label={t('target')}
        placeholder={isLoading ? t('loading') : t('select')}
        containerClassName="mb-0"
        className="bg-cardBg"
        disabled={isLoading || isSubmitting || tenantOptions.length === 0}
        hint={!isLoading && tenantOptions.length === 0 ? t('none') : undefined}
        options={tenantOptions}
        value={targetTenantId}
        onChange={setTargetTenantId}
      />
    </Modal>
  );
}
