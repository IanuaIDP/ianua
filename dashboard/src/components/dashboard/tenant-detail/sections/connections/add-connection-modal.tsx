'use client';

import { useEffect } from 'react';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { AllowedDomainsField } from '@/components/dashboard/tenant-detail/sections/connections/allowed-domains-field';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { CONNECTION_PROTOCOL_OPTIONS } from '@/constants/connection';
import { AddConnectionSchema, type AddConnectionInput } from '@/schemas/connection-schemas';

type AddConnectionModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  orgSlug?: string;
  tenantSlug?: string;
  onClose: () => void;
  onSubmit: (data: AddConnectionInput) => void;
};

const addConnectionFormId = 'add-connection-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

export function AddConnectionModal({
  isSubmitting = false,
  open,
  orgSlug,
  tenantSlug,
  onClose,
  onSubmit,
}: AddConnectionModalProps) {
  const t = useTranslations('dashboard.connections.addModal');
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<AddConnectionInput>({
    resolver: zodResolver(AddConnectionSchema),
    defaultValues: {
      allowedDomains: [],
      authorizationUrl: '',
      certificate: '',
      clientId: '',
      clientSecret: '',
      entityId: '',
      issuer: '',
      nameIdFormat: '',
      protocol: 'SAML',
      providerName: '',
      scopes: 'openid email profile',
      ssoUrl: '',
      tokenUrl: '',
    },
  });
  const protocol = useWatch({ control, name: 'protocol' });
  const isSaml = protocol === 'SAML';

  useEffect(() => {
    if (!open) {
      reset();
    }
  }, [open, reset]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={addConnectionFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={addConnectionFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Input
          label={t('providerName')}
          placeholder="Microsoft Entra ID"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('providerName')}
          error={errors.providerName}
        />
        <Controller
          control={control}
          name="protocol"
          render={({ field }) => (
            <Select
              label={t('protocol')}
              placeholder={t('protocolPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={CONNECTION_PROTOCOL_OPTIONS}
              value={field.value}
              onChange={field.onChange}
            />
          )}
        />
        <AllowedDomainsField
          control={control}
          errors={errors}
          isSubmitting={isSubmitting}
          orgSlug={orgSlug}
          setValue={setValue}
          tenantSlug={tenantSlug}
        />

        {isSaml ? (
          <>
            <Input
              label={t('entityId')}
              placeholder="https://login.microsoftonline.com/..."
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('entityId')}
              error={errors.entityId}
            />
            <Input
              label={t('ssoUrl')}
              placeholder="https://login.microsoftonline.com/.../saml2"
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('ssoUrl')}
              error={errors.ssoUrl}
            />
            <Textarea
              label={t('certificate')}
              placeholder="-----BEGIN CERTIFICATE-----"
              rows={5}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('certificate')}
              error={errors.certificate}
            />
            <Input
              label={t('nameIdFormat')}
              placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailA..."
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('nameIdFormat')}
              error={errors.nameIdFormat}
            />
          </>
        ) : (
          <>
            <Input
              label={t('issuer')}
              placeholder="https://login.microsoftonline.com/.../v2.0"
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('issuer')}
              error={errors.issuer}
            />
            <Input
              label={t('authorizationUrl')}
              placeholder="https://login.microsoftonline.com/.../oauth2/v2.0/a..."
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('authorizationUrl')}
              error={errors.authorizationUrl}
            />
            <Input
              label={t('tokenUrl')}
              placeholder="https://login.microsoftonline.com/.../oauth2/v2.0/t..."
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('tokenUrl')}
              error={errors.tokenUrl}
            />
            <Input
              label={t('clientId')}
              placeholder={t('clientIdPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('clientId')}
              error={errors.clientId}
            />
            <Input
              label={t('clientSecret')}
              placeholder={t('clientSecretPlaceholder')}
              type="password"
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('clientSecret')}
              error={errors.clientSecret}
            />
            <Input
              label={t('scopes')}
              placeholder="openid email profile"
              hint={t('scopesHint')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('scopes')}
              error={errors.scopes}
            />
          </>
        )}
      </form>
    </Modal>
  );
}
