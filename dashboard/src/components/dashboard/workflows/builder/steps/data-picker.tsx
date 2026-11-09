'use client';

import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { TRIGGER_KEY } from '@/components/dashboard/workflows/builder/constants';
import { getStepsBefore } from '@/components/dashboard/workflows/builder/graph';
import type { OperationLookup } from '@/components/dashboard/workflows/builder/step-issues';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findLoopOf, findStep } from '@/components/dashboard/workflows/builder/working-copy';
import { Input } from '@/components/ui/Input';
import { getWorkflowStepData, type WorkflowStepData } from '@/lib/api';
import type { WorkflowNode } from '@/types/workflow-graph';

type Value = WorkflowStepData['earlier'][number]['values'][number];

function getHandedOn(node: WorkflowNode, lookup: OperationLookup): Value[] {
  const named = (names: string[]): Value[] =>
    names.map((name) => ({ description: null, path: `${node.key}.${name}`, whole: false }));
  const whole: Value[] = [{ description: null, path: node.key, whole: true }];

  switch (node.kind) {
    case 'action': {
      const operation = lookup(node.integration, node.operation);

      return operation
        ? operation.outputs.map((output) => ({
            description: output.description,
            path: `${node.key}.${output.path}`,
            whole: false,
          }))
        : whole;
    }
    case 'transform':
      return named(node.fields.map((field) => field.field).filter(Boolean));
    case 'agent_run':
      return named(['answer']);
    case 'guardrail':
      return named(['checked', 'findings', 'found']);
    case 'condition':
    case 'approval':
    case 'wait':
      return [];
    default:
      return whole;
  }
}

function getEarlierInBrowser(
  nodes: WorkflowNode[],
  before: Set<string>,
  lookup: OperationLookup,
): WorkflowStepData['earlier'] {
  const sources = nodes
    .filter((node) => before.has(node.key))
    .map((node) => ({ source: node.key, values: getHandedOn(node, lookup) }))
    .filter((source) => source.values.length > 0);

  return [
    { source: TRIGGER_KEY, values: [{ description: null, path: TRIGGER_KEY, whole: true }] },
    ...sources,
  ];
}

/** What a step inside a loop may read: its item, the loop's own fields and steps before it. */
function getEarlierInLoop(
  loop: Extract<WorkflowNode, { kind: 'loop' }>,
  before: Set<string>,
  lookup: OperationLookup,
): WorkflowStepData['earlier'] {
  const fields = loop.inputs
    .filter((input) => input.field)
    .map((input) => ({ description: null, path: `trigger.${input.field}`, whole: false }));

  return [
    {
      source: TRIGGER_KEY,
      values: [
        { description: null, path: 'trigger.item', whole: true },
        { description: null, path: 'trigger.index', whole: false },
        ...fields,
      ],
    },
    ...loop.steps.nodes
      .filter((node) => before.has(node.key))
      .map((node) => ({ source: node.key, values: getHandedOn(node, lookup) }))
      .filter((source) => source.values.length > 0),
  ];
}

export function DataPicker({
  onPick,
  stepKey,
}: {
  onPick: (path: string) => void;
  stepKey: string;
}) {
  const t = useTranslations('dashboard.workflowBuilder.picker');
  const { flush, lookup, orgSlug, tenantSlug } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const revision = useWorkingCopy((state) => state.revision);
  const workflowId = useWorkingCopy((state) => state.workflowId);
  const [wholeSubPath, setWholeSubPath] = useState<Record<string, string>>({});

  useEffect(() => {
    void flush();
  }, [flush]);

  const { data: stepData } = useQuery({
    enabled: Boolean(orgSlug && workflowId),
    queryFn: () => getWorkflowStepData(orgSlug ?? '', tenantSlug, workflowId ?? ''),
    queryKey: ['workflow-step-data', orgSlug, tenantSlug, workflowId, revision],
  });

  const earlier = useMemo(() => {
    const loop = findLoopOf(copy.nodes, stepKey);

    if (loop) {
      return {
        earlier: getEarlierInLoop(loop, getStepsBefore(loop.steps.edges, stepKey), lookup),
      };
    }

    const served = stepData?.find((step) => step.key === stepKey);

    return (
      served ?? {
        earlier: getEarlierInBrowser(copy.nodes, getStepsBefore(copy.edges, stepKey), lookup),
      }
    );
  }, [copy.edges, copy.nodes, lookup, stepData, stepKey]);

  function getSourceTitle(source: string) {
    if (source === TRIGGER_KEY) {
      return t('fromTrigger');
    }

    return findStep(copy.nodes, source)?.name ?? source;
  }

  return (
    <div className="mt-2 max-h-72 overflow-auto rounded-lg bg-surfaceInset p-2">
      <p className="px-1.5 pb-2 text-xs text-textGray">{t('oneOrTheOther')}</p>
      {earlier.earlier.map((source) => (
        <div key={source.source} className="mb-2">
          <p className="px-1.5 text-xs font-semibold text-textGray">
            {getSourceTitle(source.source)}
          </p>
          {source.values.map((value) =>
            value.whole ? (
              <div key={value.path} className="mt-1 px-1.5">
                <div className="flex items-center gap-1.5">
                  <code className="shrink-0 text-xs text-primary">{value.path}.</code>
                  <Input
                    aria-label={t('subPath')}
                    containerClassName="mb-0 flex-1"
                    onChange={(event) =>
                      setWholeSubPath((current) => ({
                        ...current,
                        [value.path]: event.target.value,
                      }))
                    }
                    placeholder={t('subPathExample')}
                    value={wholeSubPath[value.path] ?? ''}
                  />
                  <button
                    type="button"
                    className="rounded-md bg-primary/15 px-2 py-1 text-xs font-semibold text-primary"
                    onClick={() => {
                      const subPath = (wholeSubPath[value.path] ?? '').replace(/^\.+|\.+$/g, '');

                      onPick(subPath ? `${value.path}.${subPath}` : value.path);
                    }}
                  >
                    {t('use')}
                  </button>
                </div>
                <p className="mt-1 text-xs text-textGray">{t('wholeHelp')}</p>
              </div>
            ) : (
              <button
                key={value.path}
                type="button"
                onClick={() => onPick(value.path)}
                className="flex w-full items-baseline justify-between gap-2 rounded-md px-1.5 py-1 text-left transition hover:bg-hoverBg"
              >
                <code className="truncate text-xs text-primary">{value.path}</code>
                {value.description ? (
                  <span className="max-w-[50%] truncate text-xs text-textGray">
                    {value.description}
                  </span>
                ) : null}
              </button>
            ),
          )}
        </div>
      ))}
    </div>
  );
}
