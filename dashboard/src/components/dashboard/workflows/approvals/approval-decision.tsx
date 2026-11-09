'use client';

import { useTranslations } from 'next-intl';

import { VerificationCodeInput } from '@/components/dashboard/shared/verification-code-input';
import { Button } from '@/components/ui/Button';

type ApprovalDecisionProps = {
  canApprove: boolean;
  code: string;
  errorMessage: string | null;
  isBusy: boolean;
  isLocked: boolean;
  needsCode: boolean;
  onApprove: () => void;
  onCodeChange: (code: string) => void;
  onDeny: () => void;
  preselectedDecision?: string;
  twoPeople: boolean;
};

/** The code box, the API's refusal and the Approve and Deny buttons. */
export function ApprovalDecision({
  canApprove,
  code,
  errorMessage,
  isBusy,
  isLocked,
  needsCode,
  onApprove,
  onCodeChange,
  onDeny,
  preselectedDecision,
  twoPeople,
}: ApprovalDecisionProps) {
  const t = useTranslations('auth.workflowApproval');

  return (
    <div className="flex flex-col gap-4">
      {twoPeople ? (
        <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs font-medium text-textGray">
          {t('twoPeople')}
        </p>
      ) : null}

      {needsCode && !isLocked ? (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-medium text-textGray">{t('codePrompt')}</span>
          <VerificationCodeInput value={code} onChange={onCodeChange} />
        </div>
      ) : null}

      {errorMessage ? (
        <p
          className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error"
          role="alert"
        >
          {errorMessage}
        </p>
      ) : null}

      <div className="flex flex-col gap-2">
        <Button
          type="button"
          isLoading={isBusy}
          disabled={!canApprove || isLocked}
          autoFocus={preselectedDecision === 'approve'}
          onClick={onApprove}
        >
          {t('approve')}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={isBusy}
          autoFocus={preselectedDecision === 'deny'}
          onClick={onDeny}
        >
          {t('deny')}
        </Button>
      </div>
    </div>
  );
}
