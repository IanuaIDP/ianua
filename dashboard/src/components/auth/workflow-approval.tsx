'use client';

import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { spinnerIcon } from '@/components/auth/token-status-screens';
import { ApprovalDecision } from '@/components/dashboard/workflows/approvals/approval-decision';
import { LoopItemsList } from '@/components/dashboard/workflows/approvals/loop-items-list';
import { JsonView } from '@/components/dashboard/workflows/json-view';
import { useTenantSessionMove } from '@/hooks/tenants/use-tenant-session-move';
import {
  approveWorkflowLoopItems,
  approveWorkflowStep,
  denyWorkflowApproval,
  getApiErrorMessage,
  getApiErrorStatus,
  getWorkflowApprovalContext,
  getWorkflowLoopApprovalPage,
  isApprovalStillWaiting,
  isStepUpRequiredError,
  loadWorkflowApproval,
} from '@/lib/api';
import { getSignInReturnHref } from '@/lib/auth/sign-in-return';
import { useAuthStore } from '@/store/auth-store';
import type { ExecutionDecided, LoopApprovalPage } from '@/types/workflows';
import { needsTwoApprovers } from '@/utils/workflow-approvals';

type WorkflowApprovalProps = {
  orgSlug: string;
  /** What the person pressed in the chat message, shown highlighted. */
  preselectedDecision?: string;
  runId: string;
  step: string;
  tenantSlug: string;
};

type Decided = 'approved' | 'counted' | 'denied';

function useApprovalSession(orgSlug: string, tenantSlug: string) {
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const access = useAuthStore((state) => state.access);
  const user = useAuthStore((state) => state.user);
  const isOrgSession = access !== null;
  const belongsHere =
    isAuthenticated &&
    user?.organizationSlug === orgSlug &&
    (isOrgSession || user?.tenantSlug === tenantSlug);
  const isMoving = useTenantSessionMove(belongsHere && isOrgSession ? tenantSlug : null);

  return {
    isReady: isHydrated && belongsHere && !isMoving,
    isSignedOut: isHydrated && !belongsHere,
  };
}

function mergeLoopPages(first: LoopApprovalPage, extra: LoopApprovalPage | null): LoopApprovalPage {
  return extra ? { ...extra, items: [...first.items, ...extra.items] } : first;
}

function resultOf(decided: ExecutionDecided, twoPeople: boolean, stillWaiting: boolean): Decided {
  return twoPeople && decided.status === 'running' && stillWaiting ? 'counted' : 'approved';
}

/** The page a chat message's Approve and Deny buttons open: nothing is decided until here. */
export function WorkflowApproval({
  orgSlug,
  preselectedDecision,
  runId,
  step,
  tenantSlug,
}: WorkflowApprovalProps) {
  const t = useTranslations('auth.workflowApproval');
  const router = useRouter();
  const { isReady, isSignedOut } = useApprovalSession(orgSlug, tenantSlug);
  const ref = { orgSlug, runId, step, tenantSlug };
  const { data, error: loadFailure } = useQuery({
    enabled: isReady,
    queryFn: () => loadWorkflowApproval(ref),
    queryKey: ['workflow-approval', orgSlug, tenantSlug, runId, step],
    retry: false,
  });
  const { data: context } = useQuery({
    enabled: isReady && data?.kind === 'step',
    queryFn: () => getWorkflowApprovalContext(ref),
    queryKey: ['workflow-approval-context', orgSlug, tenantSlug, runId, step],
    retry: false,
  });
  const [extraPage, setExtraPage] = useState<LoopApprovalPage | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [needsCode, setNeedsCode] = useState(false);
  const [code, setCode] = useState('');
  const [decided, setDecided] = useState<Decided | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [isLocked, setIsLocked] = useState(false);
  const [openedAt] = useState(() => Date.now());
  const loop = data?.kind === 'loop' ? mergeLoopPages(data.page, extraPage) : null;
  const stepData = data && data.kind === 'step' ? data : null;
  const classNeedsTwo = context ? needsTwoApprovers(context.actionClass) : false;
  const twoPeople = loop ? loop.approversNeeded >= 2 : classNeedsTwo;
  const showsCode = needsCode || twoPeople;
  const isClosed = loop !== null && Date.parse(loop.closesAt) <= openedAt;
  const loadError = loadFailure ? getApiErrorMessage(loadFailure, t('loadFailed')) : null;

  useEffect(() => {
    if (isSignedOut) {
      router.replace(getSignInReturnHref(orgSlug, tenantSlug));
    }
  }, [isSignedOut, orgSlug, router, tenantSlug]);

  function showRefusal(error: unknown) {
    if (isStepUpRequiredError(error)) {
      setNeedsCode(true);
    }

    if (getApiErrorStatus(error) === 429) {
      setIsLocked(true);
    }

    setCode('');
    setActionError(getApiErrorMessage(error, t('decideFailed')));
  }

  async function approve() {
    if (!data) {
      return;
    }

    setIsBusy(true);
    setActionError(null);

    try {
      const answer =
        data.kind === 'loop'
          ? await approveWorkflowLoopItems(ref, code || undefined)
          : await approveWorkflowStep(ref, data.shown, code || undefined);
      const stillWaiting = await isApprovalStillWaiting(data, ref);

      setDecided(resultOf(answer, twoPeople || Boolean(code), stillWaiting));
    } catch (error) {
      showRefusal(error);
    } finally {
      setIsBusy(false);
    }
  }

  async function deny() {
    setIsBusy(true);
    setActionError(null);

    try {
      await denyWorkflowApproval(ref);
      setDecided('denied');
    } catch (error) {
      showRefusal(error);
    } finally {
      setIsBusy(false);
    }
  }

  async function loadMoreItems() {
    if (!loop?.nextCursor) {
      return;
    }

    setIsBusy(true);

    try {
      const next = await getWorkflowLoopApprovalPage(ref, loop.nextCursor);

      setExtraPage(extraPage ? { ...next, items: [...extraPage.items, ...next.items] } : next);
    } catch (error) {
      setActionError(getApiErrorMessage(error, t('loadFailed')));
    } finally {
      setIsBusy(false);
    }
  }

  if (decided) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard
          title={t(`${decided}Title`)}
          subtitle={t(`${decided}Subtitle`)}
          backToLogin={false}
        >
          {null}
        </AuthCard>
      </AuthLayout>
    );
  }

  if (loadError) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <AuthCard title={t('failedTitle')} subtitle={loadError} backToLogin={false}>
          {null}
        </AuthCard>
      </AuthLayout>
    );
  }

  if (!data) {
    return (
      <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
        <div className="flex flex-col items-center gap-4 text-center">
          {spinnerIcon}
          <p className="text-sm font-medium text-textGray">{t('working')}</p>
        </div>
      </AuthLayout>
    );
  }

  const canApprove = !loop || (loop.shown >= loop.total && !isClosed);

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard
        title={context?.name ?? t('title')}
        subtitle={loop?.summary ?? context?.summary ?? t('subtitle')}
        backToLogin={false}
        width="max-w-xl"
      >
        <div className="flex flex-col gap-4">
          {stepData ? <JsonView value={stepData.shown} /> : null}
          {loop ? (
            <LoopItemsList
              isLoadingMore={isBusy}
              loop={loop}
              onLoadMore={() => void loadMoreItems()}
            />
          ) : null}
          {isClosed ? (
            <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs font-medium text-textGray">
              {t('closedNote')}
            </p>
          ) : null}
          <ApprovalDecision
            canApprove={canApprove}
            code={code}
            errorMessage={actionError}
            isBusy={isBusy}
            isLocked={isLocked}
            needsCode={showsCode}
            onApprove={() => void approve()}
            onCodeChange={setCode}
            onDeny={() => void deny()}
            preselectedDecision={preselectedDecision}
            twoPeople={twoPeople}
          />
        </div>
      </AuthCard>
    </AuthLayout>
  );
}
