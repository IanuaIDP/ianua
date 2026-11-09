'use client';

import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { getStepPorts, getStepsInOrder } from '@/components/dashboard/workflows/builder/graph';
import { StepMark } from '@/components/dashboard/workflows/builder/step-mark';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Select } from '@/components/ui/Select';
import type { WorkflowNode, WorkflowPort } from '@/types/workflow-graph';
import { cn } from '@/utils/cn';

/** The keyboard's way into the canvas: every step in order, to pick, add after, connect or remove. */
export function StepsOutline() {
  const t = useTranslations('dashboard.workflowBuilder.outline');
  const { integrations, text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const editable = useWorkingCopy((state) => state.editable);
  const selection = useWorkingCopy((state) => state.selection);
  const select = useWorkingCopy((state) => state.select);
  const openDrawer = useWorkingCopy((state) => state.openDrawer);
  const connect = useWorkingCopy((state) => state.connect);
  const disconnect = useWorkingCopy((state) => state.disconnect);
  const removeSelected = useWorkingCopy((state) => state.removeSelected);
  const order = getStepsInOrder(copy.nodes, copy.edges);

  function renderConnector(node: WorkflowNode, port: WorkflowPort, label: string) {
    const current = copy.edges.find((edge) => edge.from === node.key && edge.port === port);
    const options = order
      .filter((other) => other.key !== node.key)
      .map((other) => ({ label: other.name, value: other.key }));

    return (
      <Select
        key={port}
        containerClassName="mb-1"
        label={label}
        onChange={(to) => {
          if (current) {
            disconnect(current);
          }

          if (to) {
            connect({ from: node.key, port, to });
          }
        }}
        options={options}
        placeholder={t('leadsNowhere')}
        value={current?.to ?? ''}
      />
    );
  }

  return (
    <aside
      className="flex w-64 shrink-0 flex-col overflow-hidden rounded-lg bg-cardBg"
      aria-label={t('title')}
    >
      <p className="px-3 pt-3 text-sm font-bold text-white">{t('title')}</p>
      <div className="min-h-0 flex-1 overflow-auto p-2">
        <button
          type="button"
          onClick={() => select({ type: 'trigger' })}
          className={cn(
            'w-full rounded-lg px-2 py-1.5 text-left text-xs',
            selection?.type === 'trigger'
              ? 'bg-primary/15 text-primary'
              : 'text-white hover:bg-hoverBg',
          )}
        >
          {text.getTriggerTitle(copy.trigger)}
        </button>

        {order.map((node, index) => {
          const isSelected = selection?.type === 'step' && selection.key === node.key;
          const look =
            node.kind === 'action'
              ? (integrations.find((item) => item.key === node.integration) ?? null)
              : null;

          return (
            <div key={node.key} className="mt-1">
              <button
                type="button"
                onClick={() => select({ key: node.key, type: 'step' })}
                className={cn(
                  'flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs',
                  isSelected ? 'bg-primary/15 text-primary' : 'text-white hover:bg-hoverBg',
                )}
              >
                <span className="text-textGray">{index + 1}</span>
                <StepMark integration={look} node={node} size="sm" />
                <span className="min-w-0 truncate">{node.name}</span>
              </button>

              {isSelected && editable ? (
                <div className="mt-1 px-2 pb-2">
                  {getStepPorts(node).map((port) =>
                    renderConnector(
                      node,
                      port,
                      port === 'next'
                        ? t('thenGoesTo')
                        : port === 'when_true'
                          ? t('yesGoesTo')
                          : t('noGoesTo'),
                    ),
                  )}
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    <SmallButton
                      icon="add"
                      onClick={() => openDrawer({ after: node.key, port: getStepPorts(node)[0] })}
                    >
                      {t('addAfter')}
                    </SmallButton>
                    <SmallButton icon="delete" onClick={() => removeSelected(node.key)}>
                      {t('remove')}
                    </SmallButton>
                  </div>
                </div>
              ) : null}
            </div>
          );
        })}

        {editable ? (
          <SmallButton
            className="mt-2 w-full justify-center"
            icon="add"
            onClick={() => openDrawer(null)}
          >
            {t('addStep')}
          </SmallButton>
        ) : null}
      </div>
    </aside>
  );
}
