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
import { useOrgPasswordPolicy } from '@/hooks/auth/use-password-policy';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { usePasskeyRegistration } from '@/hooks/auth/use-passkey-registration';
import { usePasskeySupport } from '@/hooks/auth/use-passkey-support';
import {
  beginOrganizationMfa,
  changeOrganizationPassword,
  confirmOrganizationMfa,
  deriveErrorMessage,
  disableOrganizationMfa,
  getApiErrorMessage,
  getOrganizationMfaStatus,
  getOrgTrustedDevices,
  getPasskeys,
  removePasskey,
  renamePasskey,
  revokeOrgTrustedDevice,
  type BeginOrganizationMfaResponse,
  type OrganizationMfaProof,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  buildAccountSettingsPasswordSchema,
  type AccountSettingsPasswordInput,
} from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { ReenteredProof } from '@/types/auth';
import type { TrustedDevice } from '@/types/device';
import type { Passkey } from '@/types/passkey';

const passwordDefaultValues: AccountSettingsPasswordInput = {
  confirmNewPassword: '',
  currentPassword: '',
  newPassword: '',
};

export function SecuritySettingsSection() {
  const t = useTranslations('dashboard.settings.security');
  const tErrors = useTranslations('common.errors');
  const getPasswordHint = usePasswordRequirementsHint();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const passwordPolicy = useOrgPasswordPolicy(organizationSlug);
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
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return changeOrganizationPassword(organizationSlug, payload);
    },
    onSuccess: async () => {
      resetPassword(passwordDefaultValues);
      showNotification({ message: t('toasts.passwordChanged'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
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
  const [isDisableMfaModalOpen, setIsDisableMfaModalOpen] = useState(false);
  const [mfaSetup, setMfaSetup] = useState<BeginOrganizationMfaResponse | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const {
    data: mfaStatus,
    error: mfaStatusError,
    isLoading: isLoadingMfaStatus,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getOrganizationMfaStatus(organizationSlug ?? ''),
    queryKey: ['organization-mfa-status', organizationSlug],
  });
  const [isMfaProofOpen, setIsMfaProofOpen] = useState(false);
  const {
    error: beginMfaError,
    isPending: isBeginningMfa,
    mutate: beginMfaSetup,
    reset: resetBeginMfa,
  } = useMutation({
    mutationFn: (proof: ReenteredProof) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return beginOrganizationMfa(organizationSlug, proof);
    },
    onSuccess: (response) => {
      setIsMfaProofOpen(false);
      setMfaSetup(response);
    },
  });
  const { isPending: isConfirmingMfa, mutate: confirmMfaSetup } = useMutation({
    mutationFn: (code: string) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return confirmOrganizationMfa(organizationSlug, code);
    },
    onSuccess: async (codes) => {
      setMfaSetup(null);
      setRecoveryCodes(codes);
      showNotification({ message: t('toasts.mfaEnabled'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['organization-mfa-status', organizationSlug],
      });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.mfaVerifyFailed')),
        type: 'error',
      });
    },
  });
  const { isPending: isDisablingMfa, mutate: disableMfa } = useMutation({
    mutationFn: (proof: OrganizationMfaProof) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return disableOrganizationMfa(organizationSlug, proof);
    },
    onSuccess: async () => {
      setIsDisableMfaModalOpen(false);
      showNotification({ message: t('toasts.mfaDisabled'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['organization-mfa-status', organizationSlug],
      });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.mfaDisableFailed')),
        type: 'error',
      });
    },
  });

  const isPasskeySupported = usePasskeySupport();
  const passkeyRegistration = usePasskeyRegistration(organizationSlug, {
    onRegistered: async () => {
      showNotification({ message: t('toasts.passkeyAdded'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['passkeys', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
  });
  const {
    data: passkeys = [],
    error: passkeysError,
    isLoading: isLoadingPasskeys,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getPasskeys(organizationSlug ?? ''),
    queryKey: ['passkeys', organizationSlug],
  });
  const [renameTargetPasskey, setRenameTargetPasskey] = useState<Passkey | null>(null);
  const {
    error: renamePasskeyMutationError,
    isPending: isRenamingPasskey,
    mutate: submitRenamePasskey,
    reset: resetRenamePasskeyMutation,
  } = useMutation({
    mutationFn: ({ passkey, name }: { passkey: Passkey; name: string }) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return renamePasskey(organizationSlug, passkey.id, name);
    },
    onSuccess: async () => {
      setRenameTargetPasskey(null);
      await queryClient.invalidateQueries({ queryKey: ['passkeys', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
  });
  const renamePasskeyError = renamePasskeyMutationError
    ? getApiErrorMessage(renamePasskeyMutationError, t('toasts.passkeyRenameFailed'))
    : null;

  async function handleRemovePasskey(passkey: Passkey) {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await removePasskey(organizationSlug, passkey.id);
    await queryClient.invalidateQueries({ queryKey: ['passkeys', organizationSlug] });
    await invalidateAuditLogQueries(queryClient, organizationSlug);
  }

  const devicesQueryKey = ['org-trusted-devices', organizationSlug];
  const {
    data: devices = [],
    error: devicesError,
    isLoading: isLoadingDevices,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getOrgTrustedDevices(organizationSlug ?? ''),
    queryKey: devicesQueryKey,
  });

  async function handleRevokeDevice(device: TrustedDevice) {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await revokeOrgTrustedDevice(organizationSlug, device.id);
    await queryClient.invalidateQueries({ queryKey: devicesQueryKey });
    await invalidateAuditLogQueries(queryClient, organizationSlug);
  }

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

      <MfaSetupModal
        key={mfaSetup?.otpauth_uri ?? 'mfa-setup-closed'}
        isConfirming={isConfirmingMfa}
        mfaSetup={mfaSetup}
        onClose={() => setMfaSetup(null)}
        onConfirm={confirmMfaSetup}
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
        key={isDisableMfaModalOpen ? 'mfa-disable-open' : 'mfa-disable-closed'}
        isDisabling={isDisablingMfa}
        open={isDisableMfaModalOpen}
        requireCode
        onClose={() => setIsDisableMfaModalOpen(false)}
        onConfirm={(code) => {
          if (code) {
            disableMfa({ code });
          }
        }}
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
        description={t('addPasskey.description')}
        errorMessage={passkeyRegistration.confirmError}
        errorCause={passkeyRegistration.confirmErrorCause}
        requireProof
        isSubmitting={passkeyRegistration.isConfirming}
        open={Boolean(passkeyRegistration.pendingPasskey)}
        primaryActionLabel={t('addPasskey.submit')}
        title={t('addPasskey.title')}
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
    </div>
  );
}
