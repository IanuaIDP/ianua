'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Button } from '@/components/ui/Button';
import { VERIFICATION_CODE_LENGTH } from '@/constants/settings';
import { useVerifyOrganizationMfa } from '@/hooks/auth/use-verify-organization-mfa';
import { useVerifyTenantMfa } from '@/hooks/auth/use-verify-tenant-mfa';
import { getApiErrorMessage } from '@/lib/api/errors';
import type { LoginResponse } from '@/types/auth';

type MfaVerificationStepProps = {
  onBack: () => void;
  orgSlug: string;
  pendingResponse: LoginResponse;
  redirectTo?: string;
  sessionId: string;
  tenantSlug?: string;
  trustDevice?: boolean;
};

export function MfaVerificationStep({
  onBack,
  orgSlug,
  pendingResponse,
  redirectTo,
  sessionId,
  tenantSlug,
  trustDevice,
}: MfaVerificationStepProps) {
  const t = useTranslations('auth.mfa');
  const [code, setCode] = useState('');
  const orgVerifyMutation = useVerifyOrganizationMfa({
    orgSlug,
    pendingResponse,
    redirectTo,
    trustDevice,
  });
  const tenantVerifyMutation = useVerifyTenantMfa({
    context: { orgSlug, tenantSlug: tenantSlug ?? '' },
    pendingResponse,
    redirectTo,
    sessionId,
    trustDevice,
  });
  const verifyMutation = tenantSlug ? tenantVerifyMutation : orgVerifyMutation;

  function handleSubmit() {
    if (code.length !== VERIFICATION_CODE_LENGTH || verifyMutation.isPending) {
      return;
    }

    verifyMutation.mutate({ code });
  }

  return (
    <AuthCard
      title={t('requiredTitle')}
      subtitle={t('requiredSubtitle')}
      onBackToLogin={onBack}
      icon={<div className="text-[32px]">🪪</div>}
    >
      <div className="space-y-6">
        <VerificationCodeInput value={code} onChange={setCode} />

        {verifyMutation.isError && (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
            {getApiErrorMessage(verifyMutation.error, t('invalidCode'))}
          </p>
        )}

        <Button
          type="button"
          isLoading={verifyMutation.isPending}
          disabled={verifyMutation.isPending || code.length !== VERIFICATION_CODE_LENGTH}
          onClick={handleSubmit}
        >
          {t('verifyAndSignIn')}
        </Button>
      </div>
    </AuthCard>
  );
}
