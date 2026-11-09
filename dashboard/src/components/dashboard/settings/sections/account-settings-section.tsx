'use client';

import { useEffect, useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { ReenteredProofModal } from '@/components/dashboard/shared/reentered-proof-modal';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { RESEND_COOLDOWN_SECONDS } from '@/constants/settings';
import {
  getApiErrorMessage,
  getOrganizationMe,
  requestOrganizationEmailChange,
  updateOrganizationMe,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  AccountSettingsFullNameSchema,
  AccountSettingsEmailSchema,
  type AccountSettingsEmailInput,
  AccountSettingsFullNameInput,
} from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { ReenteredProof } from '@/types/auth';
import { formatCountdown } from '@/utils/countdown';

export function AccountSettingsSection() {
  const t = useTranslations('dashboard.settings.account');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const updateUser = useAuthStore((state) => state.updateUser);
  const [hasSentVerificationEmail, setHasSentVerificationEmail] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const { data: account, isFetching: isFetchingAccount } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return getOrganizationMe(organizationSlug);
    },
    queryKey: ['organization-me', organizationSlug],
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
  const [pendingEmailChange, setPendingEmailChange] = useState<AccountSettingsEmailInput | null>(
    null,
  );
  const {
    error: emailChangeError,
    isPending: isSendingEmailChangeRequest,
    mutate: submitEmailChangeRequest,
    reset: resetEmailChangeRequest,
  } = useMutation({
    mutationFn: ({
      payload,
      proof,
    }: {
      payload: AccountSettingsEmailInput;
      proof: ReenteredProof;
    }) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return requestOrganizationEmailChange(organizationSlug, payload, proof);
    },
    onSuccess: async () => {
      setPendingEmailChange(null);
      showNotification({
        message: t('toasts.emailSent'),
        type: 'success',
      });
      setHasSentVerificationEmail(true);
      setResendCooldown(RESEND_COOLDOWN_SECONDS);
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
  });
  const { isPending: isChangingFullName, mutate: submitFullNameChange } = useMutation({
    mutationFn: (payload: AccountSettingsFullNameInput) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return updateOrganizationMe(organizationSlug, payload);
    },
    onSuccess: async (updatedAccount) => {
      resetFullName({ fullName: updatedAccount.displayName });
      updateUser({ name: updatedAccount.displayName });
      showNotification({ message: t('toasts.nameUpdated'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['organization-me', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.nameFailed')),
        type: 'error',
      });
    },
  });
  useEffect(() => {
    resetFullName({ fullName: account?.displayName ?? '' });
    resetEmail({ email: account?.email ?? '' });
  }, [account?.displayName, account?.email, resetEmail, resetFullName]);

  useEffect(() => {
    if (resendCooldown <= 0) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setResendCooldown((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => window.clearTimeout(timeoutId);
  }, [resendCooldown]);

  const sendEmailChangeRequest = (data: AccountSettingsEmailInput) => {
    resetEmailChangeRequest();
    setPendingEmailChange(data);
  };

  const resendVerificationEmail = () => {
    void handleEmailSubmit(sendEmailChangeRequest)();
  };

  const saveFullName = (data: AccountSettingsFullNameInput) => {
    submitFullNameChange(data);
  };

  const discardFullNameChanges = () => {
    resetFullName({ fullName: account?.displayName ?? '' });
  };

  return (
    <div className="flex flex-col gap-4">
      <SettingsCard title={t('profile.title')} description={t('profile.description')}>
        <form className="space-y-4" onSubmit={handleFullNameSubmit(saveFullName)}>
          <Input
            label={t('profile.fullName')}
            placeholder={t('profile.fullNamePlaceholder')}
            containerClassName="mb-0 max-w-80"
            {...registerFullName('fullName')}
            error={fullNameErrors.fullName}
            disabled={isFetchingAccount || isChangingFullName}
          />

          <div className="mt-4 flex items-center gap-4">
            <Button
              type="submit"
              isLoading={isChangingFullName}
              disabled={!isFullNameDirty || isFetchingAccount || isChangingFullName}
              className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
            >
              {t('save')}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!isFullNameDirty || isFetchingAccount || isChangingFullName}
              onClick={discardFullNameChanges}
              className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
            >
              {t('discard')}
            </Button>
          </div>
        </form>
      </SettingsCard>

      <SettingsCard title={t('email.title')} description={t('email.description')}>
        <form className="space-y-4" onSubmit={handleEmailSubmit(sendEmailChangeRequest)}>
          <Input
            label={t('email.label')}
            placeholder={t('email.placeholder')}
            type="email"
            containerClassName="mb-0 max-w-80"
            {...registerEmail('email')}
            error={emailErrors.email}
            disabled={isFetchingAccount || isSendingEmailChangeRequest}
          />

          <div className="mt-4 flex items-center gap-4">
            <Button
              type="submit"
              isLoading={isSendingEmailChangeRequest}
              disabled={
                !isEmailDirty ||
                isFetchingAccount ||
                isSendingEmailChangeRequest ||
                hasSentVerificationEmail
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
                    onClick={resendVerificationEmail}
                    disabled={isFetchingAccount || isSendingEmailChangeRequest}
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

      <ReenteredProofModal
        key={pendingEmailChange ? 'email-proof-open' : 'email-proof-closed'}
        description={t('email.proofDescription')}
        error={emailChangeError}
        errorFallback={t('toasts.emailFailed')}
        isSubmitting={isSendingEmailChangeRequest}
        open={Boolean(pendingEmailChange)}
        onClose={() => setPendingEmailChange(null)}
        onSubmit={(proof) => {
          if (pendingEmailChange) {
            submitEmailChangeRequest({ payload: pendingEmailChange, proof });
          }
        }}
      />
    </div>
  );
}
