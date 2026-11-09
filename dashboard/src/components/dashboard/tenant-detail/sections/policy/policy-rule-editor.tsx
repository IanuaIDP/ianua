'use client';

import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  LIST_CONDITIONS,
  VALUELESS_CONDITIONS,
  buildAction,
  buildCondition,
} from '@/constants/policy';
import { usePolicyOptions } from '@/hooks/dashboard/use-policy-options';
import type { PolicyCondition, PolicyConditionKind, PolicyRule } from '@/types/policy';
import {
  getActionKind,
  getConditionKind,
  getConditionValue,
  getDenyReason,
  getRequiredAal,
} from '@/utils/policy';

type PolicyRuleEditorProps = {
  isBusy: boolean;
  onChange: (rule: PolicyRule) => void;
  onRemove: () => void;
  rule: PolicyRule;
};

export function PolicyRuleEditor({ isBusy, onChange, onRemove, rule }: PolicyRuleEditorProps) {
  const t = useTranslations('dashboard.policy.editor');
  const { actionOptions, conditionOptions, requiredAalOptions, riskThresholdOptions } =
    usePolicyOptions();
  const actionKind = getActionKind(rule.action);

  function replaceCondition(index: number, condition: PolicyCondition) {
    const conditions = rule.conditions.map((existing, i) => (i === index ? condition : existing));

    onChange({ ...rule, conditions });
  }

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-borderGray px-4 py-4">
      <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_auto] sm:items-start">
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          containerClassName="mb-0"
          className="bg-appBg"
          value={rule.name}
          disabled={isBusy}
          onChange={(event) => onChange({ ...rule, name: event.target.value })}
        />
        <Input
          label={t('priority')}
          type="number"
          hint={t('priorityHint')}
          containerClassName="mb-0"
          className="bg-appBg"
          value={rule.priority}
          disabled={isBusy}
          onChange={(event) => onChange({ ...rule, priority: Number(event.target.value) })}
        />
        <Button
          type="button"
          variant="outline"
          disabled={isBusy}
          onClick={onRemove}
          className="w-auto border-borderGray bg-surfaceChip px-3 py-1.5 text-xs font-medium text-error hover:bg-hoverBg sm:mt-6"
        >
          {t('remove')}
        </Button>
      </div>

      <div className="flex flex-col gap-3">
        <p className="text-xs font-semibold text-white">
          {t('whenAll')}
          {rule.conditions.length === 0 ? (
            <span className="ml-2 font-medium text-textGray">{t('noConditions')}</span>
          ) : null}
        </p>

        {rule.conditions.map((condition, index) => {
          const kind = getConditionKind(condition);
          const needsValue = !VALUELESS_CONDITIONS.includes(kind);
          const isList = LIST_CONDITIONS.includes(kind);
          const isRisk = kind === 'RiskAtLeast';

          return (
            <div
              key={`${kind}-${index}`}
              className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end"
            >
              <Select
                label={index === 0 ? t('condition') : undefined}
                containerClassName="mb-0"
                className="bg-appBg"
                options={conditionOptions}
                value={kind}
                disabled={isBusy}
                onChange={(next) =>
                  replaceCondition(index, buildCondition(next as PolicyConditionKind, ''))
                }
              />

              {isRisk ? (
                <Select
                  label={index === 0 ? t('value') : undefined}
                  containerClassName="mb-0"
                  className="bg-appBg"
                  options={riskThresholdOptions}
                  value={getConditionValue(condition)}
                  disabled={isBusy}
                  onChange={(next) => replaceCondition(index, buildCondition(kind, next))}
                />
              ) : null}

              {needsValue && !isRisk ? (
                <Input
                  label={index === 0 ? t('value') : undefined}
                  placeholder={isList ? 'GET, POST' : '/reports'}
                  containerClassName="mb-0"
                  className="bg-appBg"
                  value={getConditionValue(condition)}
                  disabled={isBusy}
                  onChange={(event) =>
                    replaceCondition(index, buildCondition(kind, event.target.value))
                  }
                />
              ) : null}

              {!needsValue ? <div className="hidden sm:block" aria-hidden /> : null}

              <Button
                type="button"
                variant="outline"
                disabled={isBusy}
                onClick={() =>
                  onChange({
                    ...rule,
                    conditions: rule.conditions.filter((_, i) => i !== index),
                  })
                }
                className="w-auto border-borderGray bg-surfaceChip px-3 py-1.5 text-xs font-medium text-textGray hover:bg-hoverBg hover:text-white"
              >
                {t('remove')}
              </Button>
            </div>
          );
        })}

        <div>
          <Button
            type="button"
            variant="outline"
            disabled={isBusy}
            onClick={() =>
              onChange({
                ...rule,
                conditions: [...rule.conditions, buildCondition('PathPrefix', '')],
              })
            }
            className="w-auto border-borderGray bg-surfaceChip px-3 py-1.5 text-xs font-medium text-white hover:bg-hoverBg"
          >
            {t('addCondition')}
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 sm:items-end">
        <Select
          label={t('then')}
          containerClassName="mb-0"
          className="bg-appBg"
          options={actionOptions}
          value={actionKind}
          disabled={isBusy}
          onChange={(next) =>
            onChange({
              ...rule,
              action: buildAction(next, getDenyReason(rule.action), getRequiredAal(rule.action)),
            })
          }
        />

        {actionKind === 'Deny' ? (
          <Input
            label={t('reason')}
            placeholder={t('reasonPlaceholder')}
            containerClassName="mb-0"
            className="bg-appBg"
            value={getDenyReason(rule.action)}
            disabled={isBusy}
            onChange={(event) =>
              onChange({ ...rule, action: buildAction('Deny', event.target.value, 'Aal2') })
            }
          />
        ) : null}

        {actionKind === 'RequireAal' ? (
          <Select
            label={t('askFor')}
            containerClassName="mb-0"
            className="bg-appBg"
            options={requiredAalOptions}
            value={getRequiredAal(rule.action)}
            disabled={isBusy}
            onChange={(next) => onChange({ ...rule, action: buildAction('RequireAal', '', next) })}
          />
        ) : null}
      </div>

      <Checkbox
        checked={rule.enabled}
        label={t('enabled')}
        name={`rule-enabled-${rule.name}`}
        disabled={isBusy}
        onChange={(event) => onChange({ ...rule, enabled: event.target.checked })}
      />
    </div>
  );
}
