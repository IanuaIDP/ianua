'use client';

import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { isValidCron } from '@/components/dashboard/workflows/builder/cron';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import {
  BeforeChangeFields,
  CompanyEventFields,
  ServiceEventFields,
  WebhookFields,
} from '@/components/dashboard/workflows/builder/steps/trigger-sources';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { WorkflowTrigger } from '@/types/workflow-graph';

const SCHEDULE_PRESETS = [
  { cron: '0 8 * * 1-5', key: 'weekdays' },
  { cron: '0 8 * * *', key: 'daily' },
  { cron: '0 * * * *', key: 'hourly' },
  { cron: '*/15 * * * *', key: 'quarterHour' },
  { cron: '0 6 1 * *', key: 'monthly' },
];

const TRIGGER_TYPES = ['manual', 'schedule', 'event', 'service', 'webhook', 'before'] as const;

function newTrigger(type: string): WorkflowTrigger {
  switch (type) {
    case 'schedule':
      return { cron: '0 8 * * 1-5', type: 'schedule' };
    case 'event':
      return { event: '', type: 'event' };
    case 'service':
      return { account_id: '', event: '', integration: '', type: 'service' };
    case 'webhook':
      return { type: 'webhook' };
    case 'before':
      return { change: 'access_given', type: 'before' };
    default:
      return { type: 'manual' };
  }
}

export function TriggerPanel({ disabled }: { disabled: boolean }) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');
  const tPreset = useLooseTranslations('dashboard.workflowBuilder.trigger.presets');
  const { text } = useBuilderContext();
  const trigger = useWorkingCopy((state) => state.copy.trigger);
  const change = useWorkingCopy((state) => state.change);

  function setTrigger(next: WorkflowTrigger) {
    change((copy) => ({ ...copy, trigger: next }));
  }

  return (
    <>
      <PanelField label={t('starts')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(type) => setTrigger(newTrigger(type))}
          options={TRIGGER_TYPES.map((type) => ({ label: t(type), value: type }))}
          value={trigger.type}
        />
      </PanelField>

      {trigger.type === 'manual' ? <PanelNote icon="touch_app">{t('manualHelp')}</PanelNote> : null}
      {trigger.type === 'event' ? (
        <CompanyEventFields disabled={disabled} onChange={setTrigger} trigger={trigger} />
      ) : null}
      {trigger.type === 'service' ? (
        <ServiceEventFields disabled={disabled} onChange={setTrigger} trigger={trigger} />
      ) : null}
      {trigger.type === 'before' ? (
        <BeforeChangeFields disabled={disabled} onChange={setTrigger} trigger={trigger} />
      ) : null}
      {trigger.type === 'webhook' ? <WebhookFields disabled={disabled} /> : null}

      {trigger.type === 'schedule' ? (
        <>
          <PanelField label={t('when')}>
            <Select
              containerClassName="mb-0"
              disabled={disabled}
              onChange={(cron) => setTrigger({ cron, type: 'schedule' })}
              options={SCHEDULE_PRESETS.map((preset) => ({
                label: tPreset(preset.key),
                value: preset.cron,
              }))}
              placeholder={t('custom')}
              value={
                SCHEDULE_PRESETS.some((preset) => preset.cron === trigger.cron) ? trigger.cron : ''
              }
            />
          </PanelField>
          <PanelField hint={t('cronHint')} label={t('cron')}>
            <Input
              aria-label={t('cron')}
              className="font-mono text-xs"
              containerClassName="mb-0"
              disabled={disabled}
              error={isValidCron(trigger.cron) ? undefined : t('cronInvalid')}
              onChange={(event) => setTrigger({ cron: event.target.value, type: 'schedule' })}
              value={trigger.cron}
            />
          </PanelField>
          {isValidCron(trigger.cron) ? (
            <PanelNote icon="schedule">
              {t('readsAs', { when: text.getCronText(trigger.cron) })}
            </PanelNote>
          ) : null}
        </>
      ) : null}
    </>
  );
}
