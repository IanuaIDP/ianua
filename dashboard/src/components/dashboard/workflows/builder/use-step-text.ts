'use client';

import { useTranslations } from 'next-intl';

import { COMPANY_INTEGRATION } from '@/components/dashboard/workflows/builder/constants';
import { describeCron } from '@/components/dashboard/workflows/builder/cron';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { WorkflowNode, WorkflowTrigger, WorkflowStepKind } from '@/types/workflow-graph';
import type { WorkflowIntegration } from '@/types/workflows';

const WEEKDAY_NAMES = [
  'sunday',
  'monday',
  'tuesday',
  'wednesday',
  'thursday',
  'friday',
  'saturday',
];

/** The words the builder shows for a step: its kind, and the plain line under its name. */
export function useStepText(integrations: WorkflowIntegration[] | undefined) {
  const t = useTranslations('dashboard.workflowBuilder.text');
  const tLoose = useLooseTranslations('dashboard.workflowBuilder.text');

  function getIntegrationTitle(key: string) {
    return integrations?.find((integration) => integration.key === key)?.title ?? key;
  }

  function getEffectText(effect: string) {
    const key = `effects.${effect}`;

    return tLoose.has(key) ? tLoose(key) : t('effects.undeclared');
  }

  function getKindLabel(kind: WorkflowStepKind) {
    return tLoose(`kinds.${kind}`);
  }

  function getKindHelp(kind: WorkflowStepKind) {
    return tLoose(`kindHelp.${kind}`);
  }

  function getCronText(cron: string) {
    const description = describeCron(cron);

    switch (description.kind) {
      case 'everyMinutes':
        return t('cron.everyMinutes', { minutes: description.minutes });
      case 'everyHour':
        return t('cron.everyHour', { minute: description.minute });
      case 'daily':
        return t('cron.daily', { time: description.time });
      case 'weekdays':
        return t('cron.weekdays', { time: description.time });
      case 'weekly':
        return t('cron.weekly', {
          day: tLoose(`weekdays.${WEEKDAY_NAMES[Number(description.day)] ?? 'sunday'}`),
          time: description.time,
        });
      case 'monthly':
        return t('cron.monthly', { day: description.day, time: description.time });
      default:
        return cron;
    }
  }

  function getTriggerTitle(trigger: WorkflowTrigger) {
    return tLoose(`triggers.${trigger.type}`);
  }

  function getTriggerLine(trigger: WorkflowTrigger) {
    switch (trigger.type) {
      case 'schedule':
        return getCronText(trigger.cron);
      case 'webhook':
        return t('triggerLines.webhook');
      case 'event':
        return trigger.event;
      case 'service':
        return t('triggerLines.service', { service: getIntegrationTitle(trigger.integration) });
      case 'before':
        return tLoose(`beforeChanges.${trigger.change}`);
      default:
        return t('triggerLines.manual');
    }
  }

  function getStepLine(node: WorkflowNode) {
    switch (node.kind) {
      case 'action':
        return node.integration === COMPANY_INTEGRATION
          ? t('lines.company', { effect: getEffectText(node.effect) })
          : t('lines.action', {
              effect: getEffectText(node.effect),
              service: getIntegrationTitle(node.integration),
            });
      case 'condition':
        return t('lines.condition', { count: node.clauses.length });
      case 'transform':
        return t('lines.transform', { count: node.fields.length });
      case 'approval':
        return node.slack
          ? t('lines.approvalSlack')
          : t('lines.approval', { hours: Math.round(node.window_seconds / 3600) });
      case 'wait':
        return node.working_hours
          ? t('lines.waitHours')
          : t('lines.wait', { duration: formatSeconds(node.duration_seconds ?? 0, t) });
      case 'loop':
        return t('lines.loop', { path: node.over });
      case 'code':
        return t('lines.code');
      case 'guardrail':
        return t('lines.guardrail');
      default:
        return t('lines.agent');
    }
  }

  return {
    getCronText,
    getEffectText,
    getIntegrationTitle,
    getKindHelp,
    getKindLabel,
    getStepLine,
    getTriggerLine,
    getTriggerTitle,
  };
}

type DurationTranslator = (
  key: 'durations.days' | 'durations.hours' | 'durations.minutes',
  values: { count: number },
) => string;

function formatSeconds(seconds: number, t: DurationTranslator) {
  if (seconds >= 86_400) {
    return t('durations.days', { count: Math.round(seconds / 86_400) });
  }

  if (seconds >= 3_600) {
    return t('durations.hours', { count: Math.round(seconds / 3_600) });
  }

  return t('durations.minutes', { count: Math.max(1, Math.round(seconds / 60)) });
}
