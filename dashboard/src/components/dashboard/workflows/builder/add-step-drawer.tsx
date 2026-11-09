'use client';

import { useMemo, useState, type DragEvent } from 'react';
import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { COMPANY_INTEGRATION } from '@/components/dashboard/workflows/builder/constants';
import { StepMark } from '@/components/dashboard/workflows/builder/step-mark';
import { STEP_DRAG_TYPE } from '@/components/dashboard/workflows/builder/workflow-canvas';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findLoopOf, findStep } from '@/components/dashboard/workflows/builder/working-copy';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import type {
  WorkflowActionStep,
  WorkflowNode,
  WorkflowStep,
  WorkflowStepKind,
} from '@/types/workflow-graph';
import type { WorkflowOperation } from '@/types/workflows';

export type DrawerItem =
  | { kind: 'action'; integration: string; operation: string }
  | { kind: Exclude<WorkflowStepKind, 'action'> };

const LOGIC_ITEMS: { icon: WorkflowStepKind }[] = [
  { icon: 'condition' },
  { icon: 'wait' },
  { icon: 'transform' },
  { icon: 'loop' },
  { icon: 'guardrail' },
  { icon: 'agent_run' },
  { icon: 'code' },
];

const RULE_OPERATIONS = ['allow', 'refuse'];

const OWN_SYSTEMS = ['apps', 'postgres', 'mysql', 'redis', 'mongodb'];

const COMPANY_TOPICS: Record<string, 'access' | 'agents' | 'people' | 'platform'> = {
  'add-to-group': 'access',
  'agent-actions': 'agents',
  'attack-mode': 'platform',
  'break-glass': 'access',
  'check-access': 'access',
  'classify-field': 'platform',
  'close-app': 'platform',
  'decide-request': 'access',
  'end-agent-run': 'agents',
  'find-person': 'people',
  'forget-devices': 'people',
  'grant-access': 'access',
  'hide-fields': 'platform',
  'invite-person': 'people',
  'list-members': 'people',
  'make-audit-pack': 'platform',
  'narrow-agent': 'agents',
  notify: 'people',
  'offer-access': 'access',
  'open-review': 'access',
  'pause-agent': 'agents',
  'pause-key': 'access',
  'read-requests': 'platform',
  'remind-until-decided': 'people',
  'remove-from-group': 'access',
  'remove-groups': 'access',
  'reset-two-step': 'people',
  'resume-key': 'access',
  'revoke-agent-tasks': 'agents',
  'revoke-keys': 'people',
  'search-audit': 'platform',
  'send-signal': 'people',
  'sign-out': 'people',
  'suggest-review': 'access',
  'suspend-person': 'people',
};

export function makeStepFromItem(
  item: DrawerItem,
  labels: { nameOf: (kind: WorkflowStepKind) => string },
  operations: WorkflowOperation[],
): { fallbackKey: string; name: string; step: WorkflowStep } | null {
  if (item.kind === 'action') {
    const operation = operations.find(
      (entry) => entry.integration === item.integration && entry.operation === item.operation,
    );

    if (!operation) {
      return null;
    }

    const step: WorkflowActionStep = {
      account_id: null,
      ceiling: operation.ceiling,
      effect: operation.effect,
      inputs: [],
      integration: operation.integration,
      kind: 'action',
      operation: operation.operation,
    };

    return { fallbackKey: operation.operation, name: operation.title, step };
  }

  const name = labels.nameOf(item.kind);

  switch (item.kind) {
    case 'condition':
      return {
        fallbackKey: 'question',
        name,
        step: {
          clauses: [{ path: '', test: 'equals', value: '' }],
          kind: 'condition',
          matching: 'all',
        },
      };
    case 'wait':
      return { fallbackKey: 'wait', name, step: { duration_seconds: 3_600, kind: 'wait' } };
    case 'transform':
      return { fallbackKey: 'data', name, step: { fields: [], kind: 'transform' } };
    case 'agent_run':
      return {
        fallbackKey: 'agent',
        name,
        step: {
          agent_id: '',
          approval_classes: [],
          goal: '',
          inputs: [],
          kind: 'agent_run',
          max_steps: 10,
          provider_id: '',
          purpose: [],
          tools: [],
        },
      };
    case 'code':
      return {
        fallbackKey: 'code',
        name,
        step: { inputs: [], kind: 'code', sandbox_version_id: '' },
      };
    case 'guardrail':
      return {
        fallbackKey: 'guardrail',
        name,
        step: { checks: ['personal_data'], kind: 'guardrail', on_finding: 'stop', text: '' },
      };
    case 'loop':
      return {
        fallbackKey: 'loop',
        name,
        step: {
          at_once: 1,
          inputs: [],
          kind: 'loop',
          most_items: 100,
          over: '',
          steps: { edges: [], nodes: [] },
        },
      };
    case 'approval':
      return {
        fallbackKey: 'approval',
        name,
        step: { action_class: 'undeclared', kind: 'approval', summary: '', window_seconds: 86_400 },
      };
    default:
      return null;
  }
}

function DrawerRow({
  description,
  icon,
  item,
  onAdd,
  title,
}: {
  description: string;
  icon: React.ReactNode;
  item: DrawerItem;
  onAdd: (item: DrawerItem) => void;
  title: string;
}) {
  function handleDragStart(event: DragEvent<HTMLButtonElement>) {
    event.dataTransfer.setData(STEP_DRAG_TYPE, JSON.stringify(item));
    event.dataTransfer.effectAllowed = 'copy';
  }

  return (
    <button
      type="button"
      draggable
      onDragStart={handleDragStart}
      onClick={() => onAdd(item)}
      className="flex w-full cursor-grab items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition hover:bg-hoverBg"
    >
      {icon}
      <span className="min-w-0">
        <span className="block truncate text-xs font-medium text-white">{title}</span>
        <span className="block truncate text-[11px] text-textGray">{description}</span>
      </span>
    </button>
  );
}

export function AddStepDrawer({ onAdd }: { onAdd: (item: DrawerItem) => void }) {
  const t = useTranslations('dashboard.workflowBuilder.drawer');
  const { accounts, integrations, operations, tenantPathFor, text } = useBuilderContext();
  const { hasPermission } = useTenantPermissions();
  const canConnectAccounts = hasPermission('Workflows', 'ConnectAccounts');
  const trigger = useWorkingCopy((state) => state.copy.trigger);
  const nodes = useWorkingCopy((state) => state.copy.nodes);
  const addingAt = useWorkingCopy((state) => state.addingAt);
  const [query, setQuery] = useState('');
  const search = query.trim().toLowerCase();
  const matches = (value: string) => !search || value.toLowerCase().includes(search);
  const addingLabel = useMemo(() => {
    if (addingAt && 'intoLoop' in addingAt) {
      return t('addingInside');
    }

    if (!addingAt || !('after' in addingAt)) {
      return null;
    }

    const from = findStep(nodes, addingAt.after);
    const name = from?.name ?? t('theTrigger');
    const to = addingAt.to ? findStep(nodes, addingAt.to)?.name : null;

    if (to) {
      return t('addingBetween', { from: name, to });
    }

    if (addingAt.port === 'when_true') {
      return t('addingYes', { from: name });
    }

    return addingAt.port === 'when_false'
      ? t('addingNo', { from: name })
      : t('addingAfter', { from: name });
  }, [addingAt, nodes, t]);

  function getGroupLabel(operation: WorkflowOperation) {
    if (operation.integration === COMPANY_INTEGRATION) {
      return t(`topics.${COMPANY_TOPICS[operation.operation] ?? 'platform'}`);
    }

    if (OWN_SYSTEMS.includes(operation.integration)) {
      return t('ownSystems');
    }

    return operation.integration === 'memory'
      ? t('memory')
      : text.getIntegrationTitle(operation.integration);
  }

  const groups = useMemo(() => {
    const connected = new Set(
      accounts
        .filter((account) => account.status !== 'disabled')
        .map((account) => account.integration),
    );
    const visible = operations.filter(
      (operation) =>
        (!operation.needsAccount || connected.has(operation.integration)) &&
        (operation.integration !== COMPANY_INTEGRATION ||
          !RULE_OPERATIONS.includes(operation.operation) ||
          trigger.type === 'before') &&
        matches(
          `${text.getIntegrationTitle(operation.integration)} ${operation.title} ${operation.description}`,
        ),
    );
    const groups = new Map<string, WorkflowOperation[]>();

    for (const operation of visible) {
      const label = getGroupLabel(operation);

      groups.set(label, [...(groups.get(label) ?? []), operation]);
    }

    return [...groups.entries()];
    // `matches` reads the search text, which is in the list below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accounts, operations, search, text, trigger.type]);

  const isInsideLoop = Boolean(
    addingAt &&
    ('intoLoop' in addingAt || ('after' in addingAt && findLoopOf(nodes, addingAt.after))),
  );
  const logicItems = LOGIC_ITEMS.filter(
    ({ icon }) => matches(text.getKindLabel(icon)) && !(icon === 'loop' && isInsideLoop),
  );
  const askMatches = matches(text.getKindLabel('approval'));

  return (
    <div className="absolute inset-x-0 top-full z-30 mt-1.5 max-h-105 overflow-auto rounded-lg bg-surfaceRaised p-4 shadow-dropdown">
      {addingLabel ? <p className="mb-2 text-xs text-primary">{addingLabel}</p> : null}
      <div className="relative mb-3 max-w-85">
        <span
          className="material-symbols-rounded absolute left-2.5 top-1/2 -translate-y-1/2 text-lg! text-textGray"
          aria-hidden="true"
        >
          search
        </span>
        <input
          aria-label={t('search')}
          autoFocus
          className="w-full rounded-lg bg-surfaceInset py-2 pl-9 pr-3 text-xs text-white placeholder-textGray outline-none focus:ring-1 focus:ring-focus"
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t('searchPlaceholder')}
          value={query}
        />
      </div>

      <div className="columns-[230px] gap-4">
        {(logicItems.length > 0 || askMatches) && (
          <div className="break-inside-avoid">
            <p className="mb-1 mt-2 px-2 text-[11px] uppercase tracking-wide text-textGray">
              {t('logic')}
            </p>
            {logicItems.map(({ icon }) => (
              <DrawerRow
                key={icon}
                description={text.getKindHelp(icon)}
                icon={<StepMark node={{ kind: icon } as WorkflowNode} size="sm" />}
                item={{ kind: icon } as DrawerItem}
                onAdd={onAdd}
                title={text.getKindLabel(icon)}
              />
            ))}
            {askMatches ? (
              <DrawerRow
                description={text.getKindHelp('approval')}
                icon={<StepMark node={{ kind: 'approval' } as WorkflowNode} size="sm" />}
                item={{ kind: 'approval' }}
                onAdd={onAdd}
                title={text.getKindLabel('approval')}
              />
            ) : null}
          </div>
        )}

        {groups.map(([label, list]) => {
          return (
            <div key={label} className="break-inside-avoid">
              <p className="mb-1 mt-2 px-2 text-[11px] uppercase tracking-wide text-textGray">
                {label}
              </p>
              {list.map((operation) => (
                <DrawerRow
                  key={`${operation.integration}/${operation.operation}`}
                  description={text.getEffectText(operation.effect)}
                  icon={
                    <StepMark
                      integration={
                        integrations.find((item) => item.key === operation.integration) ?? null
                      }
                      node={{ kind: 'action' } as WorkflowNode}
                      size="sm"
                    />
                  }
                  item={{
                    integration: operation.integration,
                    kind: 'action',
                    operation: operation.operation,
                  }}
                  onAdd={onAdd}
                  title={operation.title}
                />
              ))}
            </div>
          );
        })}
      </div>

      {logicItems.length === 0 && !askMatches && groups.length === 0 ? (
        <p className="text-xs text-textGray">{t('noMatch')}</p>
      ) : null}

      {canConnectAccounts ? (
        <Link
          href={tenantPathFor('connected-accounts')}
          className="mt-3 block rounded-lg px-2 py-1.5 text-xs font-medium text-primary hover:bg-hoverBg"
        >
          {t('connectAnother')}
        </Link>
      ) : null}
    </div>
  );
}
