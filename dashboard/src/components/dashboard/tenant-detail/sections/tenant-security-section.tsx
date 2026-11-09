'use client';

import { useMemo, useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { RecoveryCodes } from '@/components/auth/recovery-codes';
import { MfaDisableModal } from '@/components/dashboard/settings/sections/security/mfa-disable-modal';
import { MfaSetupModal } from '@/components/dashboard/settings/sections/security/mfa-setup-modal';
import { PasskeyNameModal } from '@/components/dashboard/settings/sections/security/passkey-name-modal';
import { PasskeysCard } from '@/components/dashboard/settings/sections/security/passkeys-card';
import { TrustedDevicesCard } from '@/components/dashboard/settings/sections/security/trusted-devices-card';
import { TwoFactorAuthenticationCard } from '@/components/dashboard/settings/sections/security/two-factor-authentication-card';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { ReenteredProofModal } from '@/components/dashboard/shared/reentered-proof-modal';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPasswordPolicy } from '@/hooks/auth/use-password-policy';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { usePasskeySupport } from '@/hooks/auth/use-passkey-support';
import { useTenantPasskeyRegistration } from '@/hooks/auth/use-tenant-passkey-registration';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  beginTenantMfa,
  changeTenantPassword,
  confirmTenantMfaEnrollment,
  deriveErrorMessage,
  disableTenantMfa,
  getApiErrorMessage,
  getTenantMfaStatus,
  getTenantPasskeys,
  getTrustedDevices,
  removeTenantPasskey,
  renameTenantPasskey,
  revokeTrustedDevice,
  type TenantAuthContext,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  buildAccountSettingsPasswordSchema,
  type AccountSettingsPasswordInput,
} from '@/schemas/settings-schemas';
import type { ReenteredProof } from '@/types/auth';
import type { TrustedDevice } from '@/types/device';
import type { Passkey } from '@/types/passkey';

const passwordDefaultValues: AccountSettingsPasswordInput = {
  confirmNewPassword: '',
  currentPassword: '',
  newPassword: '',
};

export function TenantSecuritySection() {
  const t = useTranslations('dashboard.settings.security');
  const tErrors = useTranslations('common.errors');
  const getPasswordHint = usePasswordRequirementsHint();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const context: TenantAuthContext | undefined =
    orgSlug && tenantSlug ? { orgSlug, tenantSlug } : undefined;
  const passwordPolicy = useTenantPasswordPolicy(orgSlug, tenantSlug);
  const passwordSchema = useMemo(
    () => buildAccountSettingsPasswordSchema(passwordPolicy, getPasswordHint(passwordPolicy)),
    [getPasswordHint, passwordPolicy],
  );
  const {
    formState: { errors: passwordErrors },
    handleSubmit: handlePasswordSubmit,
    register: registerPassword,
    reset: resetPassword,
  } = useForm<AccountSettingsPasswordInput>({
    resolver: zodResolver(passwordSchema),
    defaultValues: passwordDefaultValues,
    mode: 'onBlur',
  });
  const { isPending: isChangingPassword, mutate: submitPasswordChange } = useMutation({
    mutationFn: (payload: AccountSettingsPasswordInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return changeTenantPassword(orgSlug, tenantSlug, payload);
    },
    onSuccess: (breach) => {
      resetPassword(passwordDefaultValues);
      showNotification({
        message: breach.isBreached
          ? t('toasts.passwordChangedBreached', { count: breach.occurrences ?? 0 })
          : t('toasts.passwordChanged'),
        type: breach.isBreached ? 'default' : 'success',
      });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.passwordChangeFailed')),
        type: 'error',
      });
    },
  });
  const changePassword = (data: AccountSettingsPasswordInput) => {
    submitPasswordChange(data);
  };
  const isPasskeySupported = usePasskeySupport();
  const passkeysQueryKey = ['tenant-passkeys', orgSlug, tenantSlug];

  const passkeyRegistration = useTenantPasskeyRegistration(context, {
    onRegistered: async () => {
      showNotification({ message: t('toasts.passkeyAdded'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: passkeysQueryKey });
    },
  });
  const {
    data: passkeys = [],
    error: passkeysError,
    isLoading: isLoadingPasskeys,
  } = useQuery({
    enabled: Boolean(context),
    queryFn: () => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return getTenantPasskeys(context);
    },
    queryKey: passkeysQueryKey,
  });
  const [renameTargetPasskey, setRenameTargetPasskey] = useState<Passkey | null>(null);
  const {
    error: renamePasskeyMutationError,
    isPending: isRenamingPasskey,
    mutate: submitRenamePasskey,
    reset: resetRenamePasskeyMutation,
  } = useMutation({
    mutationFn: ({ passkey, name }: { passkey: Passkey; name: string }) => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return renameTenantPasskey(context, passkey.id, name);
    },
    onSuccess: async () => {
      setRenameTargetPasskey(null);
      await queryClient.invalidateQueries({ queryKey: passkeysQueryKey });
    },
  });
  const renamePasskeyError = renamePasskeyMutationError
    ? getApiErrorMessage(renamePasskeyMutationError, t('toasts.passkeyRenameFailed'))
    : null;

  const devicesQueryKey = ['tenant-trusted-devices', orgSlug, tenantSlug];
  const {
    data: devices = [],
    error: devicesError,
    isLoading: isLoadingDevices,
  } = useQuery({
    enabled: Boolean(context),
    queryFn: () => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return getTrustedDevices(context);
    },
    queryKey: devicesQueryKey,
  });

  async function handleRemovePasskey(passkey: Passkey) {
    if (!context) {
      throw new Error(tErrors('tenantMissing'));
    }

    await removeTenantPasskey(context, passkey.id);
    await queryClient.invalidateQueries({ queryKey: passkeysQueryKey });
  }

  async function handleRevokeDevice(device: TrustedDevice) {
    if (!context) {
      throw new Error(tErrors('tenantMissing'));
    }

    await revokeTrustedDevice(context, device.id);
    await queryClient.invalidateQueries({ queryKey: devicesQueryKey });
  }

  const [isDisableMfaModalOpen, setIsDisableMfaModalOpen] = useState(false);
  const mfaStatusQueryKey = ['tenant-mfa-status', orgSlug, tenantSlug];
  const {
    data: mfaStatus,
    error: mfaStatusError,
    isLoading: isLoadingMfaStatus,
  } = useQuery({
    enabled: Boolean(context),
    queryFn: () => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return getTenantMfaStatus(context);
    },
    queryKey: mfaStatusQueryKey,
  });

  const [mfaSetup, setMfaSetup] = useState<{ otpauth_uri: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [isMfaProofOpen, setIsMfaProofOpen] = useState(false);
  const {
    error: beginMfaError,
    isPending: isBeginningMfa,
    mutate: beginMfaSetup,
    reset: resetBeginMfa,
  } = useMutation({
    mutationFn: (proof: ReenteredProof) => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return beginTenantMfa(context, proof);
    },
    onSuccess: (response) => {
      setIsMfaProofOpen(false);
      setMfaSetup(response);
    },
  });

  const { isPending: isConfirmingMfa, mutate: confirmMfaSetup } = useMutation({
    mutationFn: (code: string) => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return confirmTenantMfaEnrollment(context, code);
    },
    onSuccess: async (codes) => {
      setMfaSetup(null);
      setRecoveryCodes(codes);
      showNotification({ message: t('toasts.mfaEnabled'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: mfaStatusQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.mfaVerifyFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isDisablingMfa, mutate: disableMfa } = useMutation({
    mutationFn: (code: string) => {
      if (!context) {
        throw new Error(tErrors('tenantMissing'));
      }

      return disableTenantMfa(context, code);
    },
    onSuccess: async () => {
      setIsDisableMfaModalOpen(false);
      showNotification({ message: t('toasts.mfaDisabled'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: mfaStatusQueryKey });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.mfaDisableFailed')),
        type: 'error',
      });
    },
  });

  return (
    <div className="flex flex-col gap-4 pb-4">
      <SettingsCard title={t('password.title')} description={t('password.description')}>
        <form className="space-y-4" onSubmit={handlePasswordSubmit(changePassword)}>
          <div className="grid gap-4 md:grid-cols-3">
            <Input
              label={t('password.current')}
              placeholder={t('password.currentPlaceholder')}
              type="password"
              containerClassName="mb-0"
              {...registerPassword('currentPassword')}
              error={passwordErrors.currentPassword}
              disabled={isChangingPassword}
            />
            <Input
              label={t('password.new')}
              placeholder={t('password.newPlaceholder')}
              type="password"
              hint={getPasswordHint(passwordPolicy)}
              containerClassName="mb-0"
              {...registerPassword('newPassword')}
              error={passwordErrors.newPassword}
              disabled={isChangingPassword}
            />
            <Input
              label={t('password.confirm')}
              placeholder={t('password.confirmPlaceholder')}
              type="password"
              containerClassName="mb-0"
              {...registerPassword('confirmNewPassword')}
              error={passwordErrors.confirmNewPassword}
              disabled={isChangingPassword}
            />
          </div>

          <Button
            type="submit"
            isLoading={isChangingPassword}
            disabled={isChangingPassword}
            className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
          >
            {t('password.submit')}
          </Button>
        </form>
      </SettingsCard>

      <TwoFactorAuthenticationCard
        isBeginningMfa={isBeginningMfa}
        isLoadingStatus={isLoadingMfaStatus}
        isMfaEnabled={mfaStatus?.enabled ?? false}
        statusErrorMessage={deriveErrorMessage([
          mfaStatusError,
          getApiErrorMessage(mfaStatusError, t('loadFailed.mfa')),
        ])}
        onDisableMfa={() => setIsDisableMfaModalOpen(true)}
        onEnableMfa={() => {
          resetBeginMfa();
          setIsMfaProofOpen(true);
        }}
      />

      <ReenteredProofModal
        key={isMfaProofOpen ? 'mfa-proof-open' : 'mfa-proof-closed'}
        description={t('mfaProof.description')}
        error={beginMfaError}
        errorFallback={t('toasts.mfaStartFailed')}
        isSubmitting={isBeginningMfa}
        open={isMfaProofOpen}
        onClose={() => setIsMfaProofOpen(false)}
        onSubmit={beginMfaSetup}
      />

      <PasskeysCard
        errorMessage={
          passkeysError
            ? getApiErrorMessage(passkeysError, t('loadFailed.passkeys'))
            : passkeyRegistration.beginError
        }
        isLoading={isLoadingPasskeys}
        isPasskeySupported={isPasskeySupported}
        isRegistering={passkeyRegistration.isBeginning}
        passkeys={passkeys}
        onAddPasskeyClick={passkeyRegistration.beginRegistration}
        onRemoveConfirm={handleRemovePasskey}
        onRenameClick={(passkey) => {
          resetRenamePasskeyMutation();
          setRenameTargetPasskey(passkey);
        }}
      />

      <TrustedDevicesCard
        devices={devices}
        errorMessage={
          devicesError ? getApiErrorMessage(devicesError, t('devices.loadFailed')) : null
        }
        isLoading={isLoadingDevices}
        onRevokeConfirm={handleRevokeDevice}
      />

      <PasskeyNameModal
        key={passkeyRegistration.pendingPasskey?.ceremonyId ?? 'add-passkey-closed'}
        description={t('addPasskey.descriptionTenant')}
        errorMessage={passkeyRegistration.confirmError}
        errorCause={passkeyRegistration.confirmErrorCause}
        requireProof
        isSubmitting={passkeyRegistration.isConfirming}
        open={Boolean(passkeyRegistration.pendingPasskey)}
        primaryActionLabel={t('addPasskey.submitTenant')}
        title={t('addPasskey.titleTenant')}
        onClose={passkeyRegistration.reset}
        onSubmit={passkeyRegistration.confirmRegistration}
      />

      <PasskeyNameModal
        key={renameTargetPasskey?.id ?? 'rename-passkey-closed'}
        defaultValue={renameTargetPasskey?.name}
        description={t('renamePasskey.description')}
        errorMessage={renamePasskeyError}
        isSubmitting={isRenamingPasskey}
        open={Boolean(renameTargetPasskey)}
        primaryActionLabel={t('renamePasskey.submit')}
        title={t('renamePasskey.title')}
        onClose={() => setRenameTargetPasskey(null)}
        onSubmit={(name) => {
          if (renameTargetPasskey) {
            submitRenamePasskey({ passkey: renameTargetPasskey, name });
          }
        }}
      />

      <MfaSetupModal
        isConfirming={isConfirmingMfa}
        mfaSetup={mfaSetup}
        onClose={() => setMfaSetup(null)}
        onConfirm={(code) => confirmMfaSetup(code)}
      />

      <Modal
        open={Boolean(recoveryCodes)}
        onClose={() => setRecoveryCodes(null)}
        dismissible={false}
        title={t('recoveryCodes.title')}
        primaryActionLabel={t('recoveryCodes.saved')}
        onPrimaryAction={() => setRecoveryCodes(null)}
        showCloseButton={false}
      >
        <RecoveryCodes codes={recoveryCodes ?? []} />
      </Modal>

      <MfaDisableModal
        isDisabling={isDisablingMfa}
        open={isDisableMfaModalOpen}
        requireCode
        onClose={() => setIsDisableMfaModalOpen(false)}
        onConfirm={(code) => {
          if (code) {
            disableMfa(code);
          }
        }}
      />
    </div>
  );
}
