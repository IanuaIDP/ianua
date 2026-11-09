'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { RESEND_COOLDOWN_SECONDS } from '@/constants/settings';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  getApiErrorMessage,
  getCurrentTenantUser,
  sendTenantUserVerification,
  updateTenantUserProfile,
} from '@/lib/api';
import {
  AccountSettingsEmailSchema,
  AccountSettingsFullNameSchema,
  type AccountSettingsEmailInput,
  type AccountSettingsFullNameInput,
} from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import { formatCountdown } from '@/utils/countdown';

export function TenantAccountSection() {
  const t = useTranslations('dashboard.settings.account');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdateProfile = hasPermission('Users', 'Update');
  const updateUser = useAuthStore((state) => state.updateUser);
  const [hasSentVerificationEmail, setHasSentVerificationEmail] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const currentUserQueryKey = ['tenant-current-user', orgSlug, tenantSlug];
  const isTenantSession = useAuthStore((state) => state.access === null);
  const { data: account, isFetching: isFetchingAccount } = useQuery({
    enabled: isTenantSession && Boolean(orgSlug && tenantSlug),
    queryFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return getCurrentTenantUser(orgSlug, tenantSlug);
    },
    queryKey: currentUserQueryKey,
  });

  const {
    formState: { errors: fullNameErrors, isDirty: isFullNameDirty },
    handleSubmit: handleFullNameSubmit,
    register: registerFullName,
    reset: resetFullName,
  } = useForm<AccountSettingsFullNameInput>({
    resolver: zodResolver(AccountSettingsFullNameSchema),
    defaultValues: {
      fullName: '',
    },
    mode: 'onBlur',
  });
  const {
    formState: { errors: emailErrors, isDirty: isEmailDirty },
    handleSubmit: handleEmailSubmit,
    register: registerEmail,
    reset: resetEmail,
  } = useForm<AccountSettingsEmailInput>({
    resolver: zodResolver(AccountSettingsEmailSchema),
    defaultValues: {
      email: '',
    },
    mode: 'onBlur',
  });
  const { isPending: isChangingFullName, mutate: submitFullNameChange } = useMutation({
    mutationFn: (payload: AccountSettingsFullNameInput) => {
      if (!orgSlug || !account) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateTenantUserProfile(orgSlug, tenantSlug, account.id, {
        displayName: payload.fullName,
      });
    },
    onSuccess: async (_, payload) => {
      resetFullName({ fullName: payload.fullName });
      updateUser({ name: payload.fullName });
      showNotification({ message: t('toasts.nameUpdated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: currentUserQueryKey });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.nameFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isChangingEmail, mutate: submitEmailChange } = useMutation({
    mutationFn: async (payload: AccountSettingsEmailInput) => {
      if (!orgSlug || !account) {
        throw new Error(tErrors('organizationMissing'));
      }

      await updateTenantUserProfile(orgSlug, tenantSlug, account.id, { email: payload.email });
      await sendTenantUserVerification(orgSlug, tenantSlug, account.id);
    },
    onSuccess: async (_, payload) => {
      resetEmail({ email: payload.email });
      showNotification({
        message: t('toasts.emailSent'),
        type: 'success',
      });
      setHasSentVerificationEmail(true);
      setResendCooldown(RESEND_COOLDOWN_SECONDS);
      await queryClient.invalidateQueries({ queryKey: currentUserQueryKey });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.emailChangeFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isResendingVerificationEmail, mutate: resendVerificationEmail } = useMutation({
    mutationFn: () => {
      if (!orgSlug || !account) {
        throw new Error(tErrors('organizationMissing'));
      }

      return sendTenantUserVerification(orgSlug, tenantSlug, account.id);
    },
    onSuccess: () => {
      showNotification({
        message: t('toasts.emailSent'),
        type: 'success',
      });
      setResendCooldown(RESEND_COOLDOWN_SECONDS);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.emailFailed')),
        type: 'error',
      });
    },
  });

  useEffect(() => {
    resetFullName({ fullName: account?.name ?? '' });
    resetEmail({ email: account?.email ?? '' });
  }, [account?.name, account?.email, resetEmail, resetFullName]);

  useEffect(() => {
    if (resendCooldown <= 0) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setResendCooldown((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => window.clearTimeout(timeoutId);
  }, [resendCooldown]);

  const saveFullName = (data: AccountSettingsFullNameInput) => {
    submitFullNameChange(data);
  };

  const saveEmail = (data: AccountSettingsEmailInput) => {
    submitEmailChange(data);
  };

  const discardFullNameChanges = () => {
    resetFullName({ fullName: account?.name ?? '' });
  };

  const isProfileBusy = isFetchingAccount || !canUpdateProfile;

  return (
    <div className="flex flex-col gap-4">
      <SettingsCard
        title={t('profile.title')}
        description={canUpdateProfile ? t('profile.description') : t('profile.managedByAdmin')}
      >
        <form className="space-y-4" onSubmit={handleFullNameSubmit(saveFullName)}>
          <Input
            label={t('profile.fullName')}
            placeholder={t('profile.fullNamePlaceholder')}
            containerClassName="mb-0 max-w-80"
            {...registerFullName('fullName')}
            error={fullNameErrors.fullName}
            disabled={isProfileBusy || isChangingFullName}
          />

          <div className="mt-4 flex items-center gap-4">
            <Button
              type="submit"
              isLoading={isChangingFullName}
              disabled={!isFullNameDirty || isProfileBusy || isChangingFullName}
              className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
            >
              {t('save')}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!isFullNameDirty || isProfileBusy || isChangingFullName}
              onClick={discardFullNameChanges}
              className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
            >
              {t('discard')}
            </Button>
          </div>
        </form>
      </SettingsCard>

      <SettingsCard title={t('email.title')} description={t('email.description')}>
        <form className="space-y-4" onSubmit={handleEmailSubmit(saveEmail)}>
          <Input
            label={t('email.label')}
            placeholder={t('email.placeholder')}
            type="email"
            containerClassName="mb-0 max-w-80"
            {...registerEmail('email')}
            error={emailErrors.email}
            disabled={isProfileBusy || isChangingEmail}
          />

          <div className="mt-4 flex items-center gap-4">
            <Button
              type="submit"
              isLoading={isChangingEmail}
              disabled={
                !isEmailDirty || isProfileBusy || isChangingEmail || hasSentVerificationEmail
              }
              className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
            >
              {t('email.send')}
            </Button>

            {hasSentVerificationEmail && (
              <p className="text-xs font-medium text-textGray">
                {t('email.didNotReceive')}{' '}
                {resendCooldown > 0 ? (
                  <span className="font-semibold text-primary ml-2">
                    {t('email.resendIn', { time: formatCountdown(resendCooldown) })}
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => resendVerificationEmail()}
                    disabled={isProfileBusy || isResendingVerificationEmail}
                    className="font-semibold ml-2 text-primary transition hover:text-primary/80 disabled:pointer-events-none disabled:opacity-40"
                  >
                    {t('email.resend')}
                  </button>
                )}
              </p>
            )}
          </div>
        </form>
      </SettingsCard>
    </div>
  );
}
