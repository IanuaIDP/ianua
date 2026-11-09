'use client';

import { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { DOMAIN_CONNECTION_IDS } from '@/constants/domain';
import { getTenantDomains } from '@/lib/api';
import { AddDomainSchema, type AddDomainInput } from '@/schemas/domain-schemas';

type AddDomainModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: AddDomainInput) => void;
  orgSlug?: string;
  tenantSlug: string;
};

const addDomainFormId = 'add-domain-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

export function AddDomainModal({
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
  orgSlug,
  tenantSlug,
}: AddDomainModalProps) {
  const t = useTranslations('dashboard.domains.addModal');
  const connectionOptions = DOMAIN_CONNECTION_IDS.map((id) => ({
    label: t(`connection.${id}`),
    value: id,
  }));
  const [isWildcard, setIsWildcard] = useState(false);
  const [parentDomainId, setParentDomainId] = useState('');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<AddDomainInput>({
    resolver: zodResolver(AddDomainSchema),
    defaultValues: {
      connection: 'Delegated',
      domain: '',
    },
  });

  if (open !== wasOpen) {
    setWasOpen(open);

    if (!open) {
      reset();
      setIsWildcard(false);
      setParentDomainId('');
    }
  }

  const { data: domainsList, isLoading: isLoadingParents } = useQuery({
    enabled: open && isWildcard && Boolean(orgSlug),
    queryFn: () =>
      getTenantDomains(orgSlug ?? '', tenantSlug, {
        limit: 100,
        sortDirection: 'asc',
        sortField: 'domain',
      }),
    queryKey: ['tenant-domains-wildcard-parents', orgSlug, tenantSlug],
  });

  const eligibleParents = (domainsList?.items ?? []).filter(
    (domain) => domain.connection === 'Delegated' && domain.verificationStatus === 'Verified',
  );
  const parentOptions = eligibleParents.map((domain) => ({
    label: domain.domain,
    value: domain.id,
  }));
  const selectedParent = eligibleParents.find((domain) => domain.id === parentDomainId);

  function handleWildcardToggle(checked: boolean) {
    setIsWildcard(checked);
    setParentDomainId('');
    setValue('connection', 'Delegated');
    setValue('domain', '');
  }

  function handleParentChange(value: string) {
    setParentDomainId(value);
    const parent = eligibleParents.find((domain) => domain.id === value);
    setValue('domain', parent ? `*.${parent.domain}` : '');
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={addDomainFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting || (isWildcard && !parentDomainId)}
    >
      <form id={addDomainFormId} className="flex flex-col gap-4" onSubmit={handleSubmit(onSubmit)}>
        <Checkbox
          checked={isWildcard}
          label={t('wildcard')}
          onChange={(event) => handleWildcardToggle(event.target.checked)}
        />

        {isWildcard ? (
          <>
            <Select
              label={t('parent')}
              placeholder={isLoadingParents ? t('parentLoading') : t('parentPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              disabled={isLoadingParents || parentOptions.length === 0}
              hint={!isLoadingParents && parentOptions.length === 0 ? t('parentHint') : undefined}
              options={parentOptions}
              value={parentDomainId}
              onChange={handleParentChange}
            />
            {selectedParent ? (
              <p className="text-xs text-textGray">
                {t.rich('willRegister', {
                  domain: selectedParent.domain,
                  name: (chunks) => <span className="font-semibold text-white">{chunks}</span>,
                })}
              </p>
            ) : null}
          </>
        ) : (
          <>
            <Input
              label={t('domain')}
              placeholder={t('domainPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('domain')}
              error={errors.domain}
            />
            <Controller
              control={control}
              name="connection"
              render={({ field }) => (
                <Select
                  label={t('dns')}
                  placeholder={t('dnsPlaceholder')}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={connectionOptions}
                  value={field.value}
                  error={errors.connection}
                  onChange={field.onChange}
                />
              )}
            />
          </>
        )}
      </form>
    </Modal>
  );
}
