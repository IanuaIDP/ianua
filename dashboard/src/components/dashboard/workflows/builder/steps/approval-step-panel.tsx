'use client';

import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import {
  ACTION_CLASSES,
  MAX_APPROVAL_WINDOW_SECONDS,
} from '@/components/dashboard/workflows/builder/constants';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findLoopOf, isLoopEntry } from '@/components/dashboard/workflows/builder/working-copy';
import { Input } from '@/components/ui/Input';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { Textarea } from '@/components/ui/Textarea';
import type { WorkflowApprovalStep, WorkflowNode } from '@/types/workflow-graph';

type ApprovalNode = WorkflowNode & WorkflowApprovalStep;

const SLACK_INTEGRATION = 'slack';

function SlackFields({ disabled, node }: { disabled: boolean; node: ApprovalNode }) {
  const t = useTranslations('dashboard.workflowBuilder.approval');
  const { accounts } = useBuilderContext();
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const slackAccounts = accounts.filter(
    (account) => account.integration === SLACK_INTEGRATION && account.status !== 'disabled',
  );
  const setSlack = (slack: WorkflowApprovalStep['slack']) =>
    updateNode(node.key, (current) => ({ ...current, slack }) as WorkflowNode);
  const slack = node.slack;

  return (
    <PanelField label={t('slack')}>
      <Switch
        checked={Boolean(slack)}
        description={t('slackHint')}
        disabled={disabled || (slackAccounts.length === 0 && !slack)}
        label={t('slackToggle')}
        onCheckedChange={(isOn) =>
          setSlack(isOn ? { account_id: slackAccounts[0]?.id ?? '', channel: '' } : undefined)
        }
      />
      {slack ? (
        <div className="mt-2 flex flex-col gap-2">
          <Select
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(account_id) => setSlack({ ...slack, account_id })}
            options={slackAccounts.map((account) => ({ label: account.name, value: account.id }))}
            placeholder={t('slackAccount')}
            value={slack.account_id}
          />
          <Input
            aria-label={t('slackChannel')}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setSlack({ ...slack, channel: event.target.value })}
            placeholder={t('slackChannel')}
            value={slack.channel}
          />
        </div>
      ) : null}
    </PanelField>
  );
}

export function ApprovalStepPanel({ disabled, node }: { disabled: boolean; node: ApprovalNode }) {
  const t = useTranslations('dashboard.workflowBuilder.approval');
  const { text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const hours = node.window_seconds ? node.window_seconds / 3600 : '';
  const loop = findLoopOf(copy.nodes, node.key);
  const canCoverLoop = loop !== null && isLoopEntry(loop, node.key);

  return (
    <>
      <PanelField hint={t('summaryHint')} label={t('summary')}>
        <Textarea
          aria-label={t('summary')}
          className="min-h-22"
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(event) =>
            updateNode(node.key, (current) => ({ ...current, summary: event.target.value }))
          }
          value={node.summary}
        />
      </PanelField>

      <PanelField hint={t('windowHint')} label={t('window')}>
        <Input
          aria-label={t('window')}
          containerClassName="mb-0"
          disabled={disabled}
          max={MAX_APPROVAL_WINDOW_SECONDS / 3600}
          min={0}
          onChange={(event) =>
            updateNode(node.key, (current) => ({
              ...current,
              window_seconds: Math.round(Number(event.target.value) * 3600),
            }))
          }
          step="any"
          type="number"
          value={String(hours)}
        />
      </PanelField>

      <PanelField hint={t('classHint')} label={t('class')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(value) =>
            updateNode(node.key, (current) => ({ ...current, action_class: value }))
          }
          options={ACTION_CLASSES.map((value) => ({
            label: text.getEffectText(value),
            value,
          }))}
          value={node.action_class}
        />
      </PanelField>

      <SlackFields disabled={disabled} node={node} />

      {canCoverLoop ? (
        <PanelField hint={t('coversHint')} label={t('covers')}>
          <SegmentedControl<NonNullable<WorkflowApprovalStep['covers']>>
            ariaLabel={t('covers')}
            onChange={(covers) => {
              if (!disabled) {
                updateNode(
                  node.key,
                  (current) =>
                    ({
                      ...current,
                      covers: covers === 'each_pass' ? undefined : covers,
                    }) as WorkflowNode,
                );
              }
            }}
            options={[
              { label: t('eachItem'), value: 'each_pass' },
              { label: t('wholeLoopOption'), value: 'whole_loop' },
            ]}
            value={node.covers ?? 'each_pass'}
          />
        </PanelField>
      ) : null}

      {node.covers === 'whole_loop' ? <PanelNote icon="repeat">{t('wholeLoop')}</PanelNote> : null}
    </>
  );
}
