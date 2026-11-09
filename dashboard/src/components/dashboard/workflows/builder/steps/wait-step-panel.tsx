'use client';

import { useTranslations } from 'next-intl';

import { MAX_WAIT_SECONDS } from '@/components/dashboard/workflows/builder/constants';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Select } from '@/components/ui/Select';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { WorkflowNode, WorkflowWaitStep, WorkflowWorkingHours } from '@/types/workflow-graph';
import { cn } from '@/utils/cn';

type WaitNode = WorkflowNode & WorkflowWaitStep;

const UNIT_SECONDS: Record<string, number> = { days: 86_400, hours: 3_600, minutes: 60 };

const WEEK = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];

function getUnit(seconds: number | undefined) {
  if (seconds && seconds % 86_400 === 0) {
    return 'days';
  }

  if (seconds && seconds % 3_600 === 0) {
    return 'hours';
  }

  return 'minutes';
}

function makeWorkingHours(): WorkflowWorkingHours {
  return {
    closes: '17:00',
    days: WEEK.slice(0, 5),
    opens: '09:00',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
}

function WorkingHoursFields({
  disabled,
  hours,
  onChange,
}: {
  disabled: boolean;
  hours: WorkflowWorkingHours;
  onChange: (hours: WorkflowWorkingHours) => void;
}) {
  const t = useTranslations('dashboard.workflowBuilder.wait');
  const tDay = useLooseTranslations('dashboard.workflowBuilder.text.weekdays');

  return (
    <>
      <PanelField label={t('days')}>
        <div className="flex flex-wrap gap-1.5">
          {WEEK.map((day) => {
            const isOn = hours.days.includes(day);

            return (
              <button
                key={day}
                type="button"
                aria-pressed={isOn}
                disabled={disabled}
                onClick={() =>
                  onChange({
                    ...hours,
                    days: isOn ? hours.days.filter((item) => item !== day) : [...hours.days, day],
                  })
                }
                className={cn(
                  'rounded-full px-3 py-1 text-xs font-medium',
                  isOn ? 'bg-primary/15 text-primary' : 'bg-surfaceChip text-textGray',
                )}
              >
                {tDay(day)}
              </button>
            );
          })}
        </div>
      </PanelField>
      <div className="mt-5 grid grid-cols-2 gap-2">
        <Input
          containerClassName="mb-0"
          disabled={disabled}
          label={t('opens')}
          onChange={(event) => onChange({ ...hours, opens: event.target.value })}
          placeholder="09:00"
          value={hours.opens}
        />
        <Input
          containerClassName="mb-0"
          disabled={disabled}
          label={t('closes')}
          onChange={(event) => onChange({ ...hours, closes: event.target.value })}
          placeholder="17:00"
          value={hours.closes}
        />
      </div>
      <PanelField hint={t('timezoneHint')} label={t('timezone')}>
        <Input
          aria-label={t('timezone')}
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(event) => onChange({ ...hours, timezone: event.target.value })}
          value={hours.timezone}
        />
      </PanelField>
    </>
  );
}

export function WaitStepPanel({ disabled, node }: { disabled: boolean; node: WaitNode }) {
  const t = useTranslations('dashboard.workflowBuilder.wait');
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const unit = getUnit(node.duration_seconds);
  const unitSeconds = UNIT_SECONDS[unit];
  const amount = node.duration_seconds ? node.duration_seconds / unitSeconds : '';
  const change = (patch: Partial<WorkflowWaitStep>) =>
    updateNode(node.key, (current) => ({ ...current, ...patch }) as WorkflowNode);

  function setDuration(nextAmount: number, nextUnit: string) {
    change({ duration_seconds: Math.round(nextAmount * UNIT_SECONDS[nextUnit]) });
  }

  function setMode(mode: 'hours' | 'time') {
    if (disabled) {
      return;
    }

    change(
      mode === 'hours'
        ? { duration_seconds: undefined, working_hours: makeWorkingHours() }
        : { duration_seconds: 3_600, working_hours: undefined },
    );
  }

  return (
    <>
      <PanelField label={t('mode')}>
        <SegmentedControl
          ariaLabel={t('mode')}
          onChange={setMode}
          options={[
            { label: t('forATime'), value: 'time' },
            { label: t('untilHours'), value: 'hours' },
          ]}
          value={node.working_hours ? 'hours' : 'time'}
        />
      </PanelField>

      {node.working_hours ? (
        <WorkingHoursFields
          disabled={disabled}
          hours={node.working_hours}
          onChange={(working_hours) => change({ working_hours })}
        />
      ) : (
        <>
          <div className="mt-5 grid grid-cols-2 gap-2">
            <Input
              aria-label={t('howLong')}
              containerClassName="mb-0"
              disabled={disabled}
              label={t('howLong')}
              min={0}
              onChange={(event) => setDuration(Number(event.target.value), unit)}
              step="any"
              type="number"
              value={String(amount)}
            />
            <Select
              containerClassName="mb-0"
              disabled={disabled}
              label={t('unit')}
              onChange={(value) => setDuration(Number(amount) || 1, value)}
              options={[
                { label: t('minutes'), value: 'minutes' },
                { label: t('hours'), value: 'hours' },
                { label: t('days'), value: 'days' },
              ]}
              value={unit}
            />
          </div>
          <PanelNote icon="hourglass_top">
            {t('limit', { days: MAX_WAIT_SECONDS / 86_400 })}
          </PanelNote>
        </>
      )}
    </>
  );
}
