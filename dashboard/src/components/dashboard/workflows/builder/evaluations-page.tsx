'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useWorkflowRouteParams } from '@/components/dashboard/workflows/builder/use-workflow-route-params';
import { ClearanceSelect } from '@/components/dashboard/workflows/clearance-select';
import { JsonEditor, parseJsonObject } from '@/components/dashboard/workflows/json-editor';
import { WithheldNotice } from '@/components/dashboard/workflows/withheld-notice';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import {
  getApiErrorMessage,
  getBuilderWorkflow,
  getWorkflowEvaluations,
  getWorkflowEvaluationSet,
  saveWorkflowEvaluationSet,
  startWorkflowEvaluation,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type {
  Evaluation,
  EvaluationCaseBody,
  EvaluationCheckBody,
  EvaluationSet,
} from '@/types/workflow-evaluation';
import type { ExposureLevel } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';

const MAX_CASES = 50;
const MAX_CHECKS = 10;
const POLL_MS = 5_000;

type CheckRow = { at: string; expected: string; kind: EvaluationCheckBody['kind'] };

type CaseRow = {
  checks: CheckRow[];
  exposure: ExposureLevel;
  input: string;
  name: string;
};

function toExpected(check: EvaluationCheckBody) {
  if (check.kind === 'contains') {
    return check.text ?? '';
  }

  if (check.kind === 'matches') {
    return check.pattern ?? '';
  }

  return typeof check.value === 'string' ? check.value : JSON.stringify(check.value ?? '');
}

function toRows(set: EvaluationSet): CaseRow[] {
  return set.cases
    .filter((item) => !item.withheld)
    .map((item) => ({
      checks: (item.checks ?? []).map((check) => ({
        at: check.at,
        expected: toExpected(check),
        kind: check.kind,
      })),
      exposure: item.exposure as ExposureLevel,
      input: JSON.stringify(item.input ?? {}, null, 2),
      name: item.name,
    }));
}

function parseExpected(text: string) {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function toCheckBody(row: CheckRow): EvaluationCheckBody {
  if (row.kind === 'contains') {
    return { at: row.at, kind: 'contains', text: row.expected };
  }

  if (row.kind === 'matches') {
    return { at: row.at, kind: 'matches', pattern: row.expected };
  }

  return { at: row.at, kind: 'equals', value: parseExpected(row.expected) };
}

function toCaseBodies(rows: CaseRow[]): EvaluationCaseBody[] | null {
  const bodies: EvaluationCaseBody[] = [];

  for (const row of rows) {
    const input = parseJsonObject(row.input);

    if (input === null || !row.name.trim() || row.checks.length === 0) {
      return null;
    }

    bodies.push({
      checks: row.checks.map(toCheckBody),
      exposure: row.exposure,
      input,
      name: row.name.trim(),
    });
  }

  return bodies;
}

function CaseEditor({
  canEdit,
  onChange,
  onRemove,
  row,
}: {
  canEdit: boolean;
  onChange: (row: CaseRow) => void;
  onRemove: () => void;
  row: CaseRow;
}) {
  const t = useTranslations('dashboard.workflowBuilder.evaluations');

  function setCheck(index: number, next: CheckRow) {
    onChange({
      ...row,
      checks: row.checks.map((check, position) => (position === index ? next : check)),
    });
  }

  return (
    <li className="rounded-lg bg-surfaceInset p-3">
      <div className="grid gap-2 sm:grid-cols-2">
        <Input
          containerClassName="mb-0"
          disabled={!canEdit}
          label={t('caseName')}
          onChange={(event) => onChange({ ...row, name: event.target.value })}
          value={row.name}
        />
        <ClearanceSelect
          label={t('exposure')}
          onChange={(exposure) => onChange({ ...row, exposure })}
          value={row.exposure}
        />
      </div>
      <div className="mt-3">
        <JsonEditor
          error={parseJsonObject(row.input) === null ? t('notJson') : undefined}
          id={`case-input-${row.name}`}
          label={t('input')}
          onChange={(input) => onChange({ ...row, input })}
          value={row.input}
        />
      </div>
      <p className="mt-3 text-xs font-semibold text-white">{t('checks')}</p>
      {row.checks.map((check, index) => (
        <div key={index} className="mt-2 grid grid-cols-[1fr_8rem_1fr_auto] items-center gap-1.5">
          <Input
            aria-label={t('at')}
            containerClassName="mb-0"
            disabled={!canEdit}
            onChange={(event) => setCheck(index, { ...check, at: event.target.value })}
            placeholder={t('atExample')}
            value={check.at}
          />
          <Select
            containerClassName="mb-0"
            disabled={!canEdit}
            onChange={(kind) =>
              setCheck(index, { ...check, kind: kind as EvaluationCheckBody['kind'] })
            }
            options={[
              { label: t('kinds.equals'), value: 'equals' },
              { label: t('kinds.contains'), value: 'contains' },
              { label: t('kinds.matches'), value: 'matches' },
            ]}
            value={check.kind}
          />
          <Input
            aria-label={t('expected')}
            containerClassName="mb-0"
            disabled={!canEdit}
            onChange={(event) => setCheck(index, { ...check, expected: event.target.value })}
            placeholder={t('expected')}
            value={check.expected}
          />
          <button
            type="button"
            aria-label={t('removeCheck')}
            disabled={!canEdit}
            onClick={() =>
              onChange({ ...row, checks: row.checks.filter((_, position) => position !== index) })
            }
            className="flex size-7 items-center justify-center rounded-md text-textGray hover:text-white"
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              close
            </span>
          </button>
        </div>
      ))}
      {canEdit ? (
        <div className="mt-2 flex gap-2">
          <SmallButton
            disabled={row.checks.length >= MAX_CHECKS}
            icon="add"
            onClick={() =>
              onChange({
                ...row,
                checks: [...row.checks, { at: '', expected: '', kind: 'equals' }],
              })
            }
          >
            {t('addCheck')}
          </SmallButton>
          <SmallButton icon="delete" onClick={onRemove}>
            {t('removeCase')}
          </SmallButton>
        </div>
      ) : null}
    </li>
  );
}

function CasesForm({
  canEdit,
  onSaved,
  set,
  workflowId,
}: {
  canEdit: boolean;
  onSaved: () => void;
  set: EvaluationSet;
  workflowId: string;
}) {
  const t = useTranslations('dashboard.workflowBuilder.evaluations');
  const { showNotification } = useNotification();
  const { orgSlug, tenantSlug } = useWorkflowRouteParams();
  const queryClient = useQueryClient();
  const [rows, setRows] = useState(() => toRows(set));
  const [isGateOn, setIsGateOn] = useState(set.publishGate === 'must_pass');
  const withheld = set.cases.filter((item) => item.withheld);
  const bodies = toCaseBodies(rows);

  const { isPending, mutate } = useMutation({
    mutationFn: () =>
      saveWorkflowEvaluationSet(orgSlug ?? '', tenantSlug, workflowId, {
        cases: bodies ?? [],
        publishGate: isGateOn ? 'must_pass' : 'off',
      }),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('saveFailed')), type: 'error' });
    },
    onSuccess: async () => {
      showNotification({ message: t('saved'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onSaved();
    },
  });

  return (
    <section className="rounded-lg border border-borderGray bg-cardBg p-4">
      <h2 className="text-sm font-bold text-white">{t('cases')}</h2>
      <p className="mt-1 text-xs text-textGray">{t('casesHelp', { most: MAX_CASES })}</p>

      {withheld.length > 0 ? (
        <div className="mt-3 flex flex-col gap-1">
          {withheld.map((item) => (
            <div key={item.name}>
              <p className="text-xs font-semibold text-white">{item.name}</p>
              <WithheldNotice />
            </div>
          ))}
          <p className="text-xs text-orange">{t('withheldBlocksSaving')}</p>
        </div>
      ) : null}

      {rows.length === 0 ? <p className="mt-3 text-sm text-textGray">{t('noCases')}</p> : null}

      <ul className="mt-3 flex flex-col gap-3">
        {rows.map((row, index) => (
          <CaseEditor
            key={index}
            canEdit={canEdit}
            onChange={(next) =>
              setRows(rows.map((item, position) => (position === index ? next : item)))
            }
            onRemove={() => setRows(rows.filter((_, position) => position !== index))}
            row={row}
          />
        ))}
      </ul>

      {canEdit ? (
        <div className="mt-3">
          <SmallButton
            disabled={rows.length + withheld.length >= MAX_CASES}
            icon="add"
            onClick={() =>
              setRows([
                ...rows,
                {
                  checks: [{ at: '', expected: '', kind: 'equals' }],
                  exposure: 'internal',
                  input: '{}',
                  name: '',
                },
              ])
            }
          >
            {t('addCase')}
          </SmallButton>
        </div>
      ) : null}

      <div className="mt-4 border-t border-borderGray pt-4">
        <Switch
          checked={isGateOn}
          description={t('gateHelp')}
          disabled={!canEdit}
          label={t('gate')}
          onCheckedChange={setIsGateOn}
        />
      </div>

      {canEdit ? (
        <Button
          className="mt-4 w-auto py-1.5"
          disabled={bodies === null || withheld.length > 0}
          isLoading={isPending}
          onClick={() => mutate()}
        >
          {t('save')}
        </Button>
      ) : null}
    </section>
  );
}

function EvaluationResults({
  evaluation,
  workflowPath,
}: {
  evaluation: Evaluation;
  workflowPath: string;
}) {
  const t = useTranslations('dashboard.workflowBuilder.evaluations');
  const tOutcome = useLooseTranslations('dashboard.workflowBuilder.evaluations.outcomes');
  const tReason = useLooseTranslations('dashboard.workflowBuilder.evaluations.reasons');

  return (
    <li className="rounded-lg bg-surfaceInset p-3">
      <p className="text-xs text-white">
        <span className="font-semibold">
          {tOutcome.has(evaluation.status) ? tOutcome(evaluation.status) : evaluation.status}
        </span>
        <span className="text-textGray">
          {' · '}
          {t('versionNumber', { number: evaluation.version })}
          {' · '}
          {formatBackendDateTime(evaluation.createdAt)}
        </span>
      </p>
      <ul className="mt-2 flex flex-col gap-1.5">
        {evaluation.cases.map((result) => (
          <li key={result.case.name} className="text-xs text-textGray">
            <span className="text-white">{result.case.name}</span>
            {': '}
            {tOutcome.has(result.outcome) ? tOutcome(result.outcome) : result.outcome}
            {result.reason
              ? ` (${tReason.has(result.reason) ? tReason(result.reason) : result.reason})`
              : ''}
            {result.withheldExposure ? ` · ${t('differencesWithheld')}` : ''}
            {result.executionId ? (
              <>
                {' · '}
                <Link
                  className="text-primary hover:underline"
                  href={`${workflowPath}?run=${result.executionId}`}
                >
                  {t('openRun')}
                </Link>
              </>
            ) : null}
            {result.differences?.map((difference, index) => (
              <p key={index} className="mt-0.5">
                {difference.kind === 'run_ended'
                  ? t('runEnded', { end: difference.runEnd ?? '' })
                  : t('checkDiffered', {
                      check: (difference.check ?? 0) + 1,
                      found: difference.found ?? t('nothingFound'),
                    })}
              </p>
            ))}
          </li>
        ))}
      </ul>
    </li>
  );
}

/** Sample cases for a workflow, the evaluations run on them, and the publishing gate. */
export default function EvaluationsPage() {
  const t = useTranslations('dashboard.workflowBuilder.evaluations');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const navLabels = useNavLabels();
  const { isTenantView, orgSlug, tenantSlug, workflowId } = useWorkflowRouteParams();
  const { hasPermission } = useTenantPermissions();
  const handleSectionChange = useTenantSectionNavigation(tenantSlug);
  const canUpdate = hasPermission('Workflows', 'Update');
  const canEvaluate = canUpdate && hasPermission('Workflows', 'Run');
  const workflowsPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'workflows',
    'workflows',
  );
  const workflowPath = `${workflowsPath}/${workflowId}`;
  const isReady = Boolean(orgSlug && workflowId);

  const { data: workflow } = useQuery({
    enabled: isReady,
    queryFn: () => getBuilderWorkflow(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    queryKey: ['workflow-builder-latest', orgSlug, tenantSlug, workflowId],
  });
  const {
    data: set,
    dataUpdatedAt,
    error,
  } = useQuery({
    enabled: isReady,
    queryFn: () => getWorkflowEvaluationSet(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    queryKey: ['workflow-evaluation-set', orgSlug, tenantSlug, workflowId],
    refetchOnWindowFocus: false,
  });
  const { data: evaluations } = useQuery({
    enabled: isReady,
    queryFn: () => getWorkflowEvaluations(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    queryKey: ['workflow-evaluations', orgSlug, tenantSlug, workflowId],
    refetchInterval: (query) => (query.state.data?.[0]?.status === 'running' ? POLL_MS : false),
  });

  const { isPending: isStarting, mutate: evaluate } = useMutation({
    mutationFn: () => startWorkflowEvaluation(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('startFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ['workflow-evaluations', orgSlug, tenantSlug, workflowId],
      });
    },
  });

  const name = workflow?.name ?? '';
  const isDraft = workflow?.status === 'draft';
  const trail = [
    { href: workflowsPath, title: navLabels.label('Workflows') },
    { href: workflowPath, title: name },
    { title: t('title') },
  ];

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Workflows"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleSectionChange}
        />
      ) : null}
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={trail} />
        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <div className="mx-auto flex w-full max-w-240 flex-col gap-4">
            {error ? (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
                {getApiErrorMessage(error, t('loadFailed'))}
              </p>
            ) : null}

            {set && workflowId ? (
              <CasesForm
                key={dataUpdatedAt}
                canEdit={canUpdate}
                onSaved={() =>
                  void queryClient.invalidateQueries({
                    queryKey: ['workflow-evaluation-set', orgSlug, tenantSlug, workflowId],
                  })
                }
                set={set}
                workflowId={workflowId}
              />
            ) : null}

            <section className="rounded-lg border border-borderGray bg-cardBg p-4">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-sm font-bold text-white">{t('evaluations')}</h2>
                {canEvaluate ? (
                  <Button
                    className="w-auto py-1.5"
                    disabled={!isDraft || !set?.cases.length}
                    isLoading={isStarting}
                    onClick={() => evaluate()}
                  >
                    {t('evaluate')}
                  </Button>
                ) : null}
              </div>
              {!isDraft && workflow ? (
                <p className="mt-1 text-xs text-textGray">{t('onlyDrafts')}</p>
              ) : null}
              {evaluations?.length === 0 ? (
                <p className="mt-3 text-sm text-textGray">{t('noEvaluations')}</p>
              ) : null}
              <ul className="mt-3 flex flex-col gap-2">
                {evaluations?.map((evaluation) => (
                  <EvaluationResults
                    key={evaluation.id}
                    evaluation={evaluation}
                    workflowPath={workflowPath}
                  />
                ))}
              </ul>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
