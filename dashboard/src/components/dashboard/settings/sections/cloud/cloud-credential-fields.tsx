'use client';

import { useTranslations } from 'next-intl';
import type { FieldErrors, UseFormRegister } from 'react-hook-form';

import { Input } from '@/components/ui/Input';
import { Textarea } from '@/components/ui/Textarea';
import type { CloudCredentialInput } from '@/schemas/cloud-schemas';
import type { CloudProviderId } from '@/types/cloud-account';

type CloudCredentialFieldsProps = {
  disabled?: boolean;
  errors: FieldErrors<CloudCredentialInput>;
  provider: CloudProviderId;
  register: UseFormRegister<CloudCredentialInput>;
};

export function CloudCredentialFields({
  disabled = false,
  errors,
  provider,
  register,
}: CloudCredentialFieldsProps) {
  const t = useTranslations('dashboard.settings.cloud');

  if (provider === 'aws') {
    return (
      <Input
        label={t('fields.roleArn')}
        placeholder="arn:aws:iam::123456789012:role/IanuaConnect"
        hint={t('fields.roleArnHint')}
        containerClassName="mb-0"
        {...register('roleArn')}
        error={'roleArn' in errors ? errors.roleArn : undefined}
        disabled={disabled}
      />
    );
  }

  if (provider === 'gcp') {
    return (
      <>
        <Input
          label={t('fields.serviceAccountEmail')}
          placeholder="ianua@your-project.iam.gserviceaccount.com"
          containerClassName="mb-0"
          {...register('clientEmail')}
          error={'clientEmail' in errors ? errors.clientEmail : undefined}
          disabled={disabled}
        />
        <Textarea
          label={t('fields.serviceAccountKey')}
          placeholder='{"type":"service_account", ...}'
          hint={t('fields.serviceAccountKeyHint')}
          rows={5}
          containerClassName="mb-0"
          {...register('key')}
          error={'key' in errors ? errors.key : undefined}
          disabled={disabled}
        />
      </>
    );
  }

  if (provider === 'azure') {
    return (
      <>
        <Input
          label={t('fields.directoryId')}
          placeholder="00000000-0000-0000-0000-000000000000"
          containerClassName="mb-0"
          {...register('directoryId')}
          error={'directoryId' in errors ? errors.directoryId : undefined}
          disabled={disabled}
        />
        <Input
          label={t('fields.applicationId')}
          placeholder="00000000-0000-0000-0000-000000000000"
          containerClassName="mb-0"
          {...register('clientId')}
          error={'clientId' in errors ? errors.clientId : undefined}
          disabled={disabled}
        />
        <Input
          label={t('fields.clientSecret')}
          type="password"
          placeholder={t('fields.clientSecretPlaceholder')}
          containerClassName="mb-0"
          {...register('secret')}
          error={'secret' in errors ? errors.secret : undefined}
          disabled={disabled}
        />
      </>
    );
  }

  if (provider === 'kubernetes') {
    return (
      <>
        <Input
          label={t('fields.apiServer')}
          placeholder="https://cluster.example.com:6443"
          hint={t('fields.apiServerHint')}
          containerClassName="mb-0"
          {...register('server')}
          error={'server' in errors ? errors.server : undefined}
          disabled={disabled}
        />
        <Textarea
          label={t('fields.caCertificate')}
          placeholder="-----BEGIN CERTIFICATE-----"
          hint={t('fields.caCertificateHint')}
          rows={5}
          containerClassName="mb-0"
          {...register('caCertificate')}
          error={'caCertificate' in errors ? errors.caCertificate : undefined}
          disabled={disabled}
        />
        <Input
          label={t('fields.serviceAccountToken')}
          type="password"
          placeholder={t('fields.serviceAccountTokenPlaceholder')}
          hint={t('fields.serviceAccountTokenHint')}
          containerClassName="mb-0"
          {...register('token')}
          error={'token' in errors ? errors.token : undefined}
          disabled={disabled}
        />
      </>
    );
  }

  return (
    <Input
      label={t('fields.accessToken')}
      type="password"
      placeholder="dop_v1_..."
      hint={t('fields.accessTokenHint')}
      containerClassName="mb-0"
      {...register('token')}
      error={'token' in errors ? errors.token : undefined}
      disabled={disabled}
    />
  );
}
