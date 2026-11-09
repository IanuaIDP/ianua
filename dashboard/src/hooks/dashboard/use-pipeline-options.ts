import { useTranslations } from 'next-intl';

import type { MultiSelectOption } from '@/components/ui/MultiSelect';
import {
  CONFIGURABLE_STAGE_KINDS,
  LLM_DIALECTS,
  RATE_LIMIT_KEY_BY_IDS,
  WAF_RULE_SETS,
} from '@/constants/pipeline';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SelectOption } from '@/types/dashboard';
import type { StageKind } from '@/types/pipeline';

/** Stage kinds and the choices of the stage forms, worded in the current language. */
export function usePipelineOptions() {
  const t = useTranslations('dashboard.pipelines');
  const tKinds = useLooseTranslations('dashboard.pipelines.stageKinds');
  const tDescriptions = useLooseTranslations('dashboard.pipelines.stageDescriptions');

  const stageKindLabel = (kind: StageKind) => (tKinds.has(kind) ? tKinds(kind) : kind);
  const stageKindDescription = (kind: StageKind) =>
    tDescriptions.has(kind) ? tDescriptions(kind) : '';

  const addableStageKindOptions: SelectOption[] = CONFIGURABLE_STAGE_KINDS.map((kind) => ({
    label: stageKindLabel(kind),
    value: kind,
  }));
  const wafRuleSetOptions: MultiSelectOption[] = WAF_RULE_SETS.map((ruleSet) => ({
    label: t(`addStage.wafRuleSets.${ruleSet}`),
    value: ruleSet,
  }));
  const rateLimitKeyByOptions: SelectOption[] = RATE_LIMIT_KEY_BY_IDS.map((id) => ({
    label: t(`addStage.keyBy.${id}`),
    value: id,
  }));
  const llmDialectOptions = LLM_DIALECTS.map((dialect) => ({
    label: t(`addStage.dialects.${dialect}`),
    value: dialect,
  }));

  return {
    addableStageKindOptions,
    llmDialectOptions,
    rateLimitKeyByOptions,
    stageKindDescription,
    stageKindLabel,
    wafRuleSetOptions,
  };
}
