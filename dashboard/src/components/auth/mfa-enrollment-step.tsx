'use client';

import { useEffect, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { QRCodeSVG } from 'qrcode.react';

import { AuthCard } from '@/components/auth/AuthCard';
import { RecoveryCodes } from '@/components/auth/recovery-codes';
import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Button } from '@/components/ui/Button';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import { getApiErrorMessage } from '@/lib/api/errors';
import {
  beginTenantMfa,
  confirmTenantMfaEnrollment,
  type TenantAuthContext,
} from '@/lib/api/services/auth';
import { trustCurrentDevice, trustCurrentOrgDevice } from '@/lib/api/services/devices';
import { beginOrganizationMfa, confirmOrganizationMfa } from '@/lib/api/services/organizations';
import { useApplyPasskeyLogin } from '@/hooks/auth/use-apply-passkey-login';
import { useApplyTenantPasskeyLogin } from '@/hooks/auth/use-apply-tenant-passkey-login';
import type { LoginResponse } from '@/types/auth';

type MfaEnrollmentStepProps = {
  onBack: () => void;
  orgSlug: string;
  pendingResponse: LoginResponse;
  redirectTo?: string;
  sessionId: string;
  /** The workspace signed in to; absent for an organization administrator. */
  tenantSlug?: string;
  trustDevice?: boolean;
};

/**
 * The step a sign-in passes through when a second factor is required and the
 * person has none yet: scan, confirm, keep the recovery codes, go in.
 */
export function MfaEnrollmentStep({
  onBack,
  orgSlug,
  pendingResponse,
  redirectTo,
  sessionId,
  tenantSlug,
  trustDevice,
}: MfaEnrollmentStepProps) {
  const t = useTranslations('auth.mfa');
  const applyOrganizationLogin = useApplyPasskeyLogin({ redirectTo });
  const applyTenantLogin = useApplyTenantPasskeyLogin({ redirectTo });
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const hasStarted = useRef(false);
  const workspace: TenantAuthContext | null = tenantSlug ? { orgSlug, tenantSlug } : null;

  const begin = useMutation({
    mutationFn: () => (workspace ? beginTenantMfa(workspace) : beginOrganizationMfa(orgSlug)),
  });
  const confirm = useMutation({
    mutationFn: (entered: string) =>
      workspace
        ? confirmTenantMfaEnrollment(workspace, entered, sessionId)
        : confirmOrganizationMfa(orgSlug, entered, sessionId),
    onSuccess: setRecoveryCodes,
  });

  useEffect(() => {
    if (hasStarted.current) {
      return;
    }

    hasStarted.current = true;
    begin.mutate();
  }, [begin]);

  const enter = useMutation({
    mutationFn: async () => {
      await (workspace ? applyTenantLogin : applyOrganizationLogin)(pendingResponse);

      if (trustDevice) {
        await (workspace ? trustCurrentDevice(workspace) : trustCurrentOrgDevice(orgSlug));
      }
    },
  });

  if (recoveryCodes) {
    return (
      <AuthCard
        title={t('enrollmentDoneTitle')}
        subtitle={t('enrollmentDoneSubtitle')}
        backToLogin={false}
      >
        <div className="space-y-6">
          <RecoveryCodes codes={recoveryCodes} />

          {enter.isError ? (
            <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {getApiErrorMessage(enter.error, t('setupFailed'))}
            </p>
          ) : null}

          <Button
            type="button"
            isLoading={enter.isPending}
            disabled={enter.isPending}
            onClick={() => enter.mutate()}
          >
            {t('savedContinue')}
          </Button>
        </div>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title={t('enrollTitle')}
      subtitle={workspace ? t('enrollSubtitle') : t('enrollSubtitleOrganization')}
      onBackToLogin={onBack}
    >
      <div className="space-y-6">
        <div className="flex min-h-34 items-center justify-center rounded-[10px] bg-white p-3">
          {begin.data?.otpauth_uri ? (
            <QRCodeSVG
              value={begin.data.otpauth_uri}
              size={112}
              bgColor="transparent"
              fgColor="#1d1d1d"
              level="M"
              title={t('qrTitle')}
            />
          ) : null}
        </div>

        <VerificationCodeInput value={code} onChange={setCode} />

        {begin.isError || confirm.isError ? (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
            {getApiErrorMessage(begin.error ?? confirm.error, t('setupFailed'))}
          </p>
        ) : null}

        <Button
          type="button"
          isLoading={confirm.isPending}
          disabled={confirm.isPending || code.length !== VERIFICATION_CODE_LENGTH}
          onClick={() => confirm.mutate(code)}
        >
          {t('verifyAndSignIn')}
        </Button>
      </div>
    </AuthCard>
  );
}
