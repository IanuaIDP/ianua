'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import { HeaderEntriesField } from '@/components/dashboard/tenant-detail/sections/pipeline/header-entries-field';
import { WasmModuleField } from '@/components/dashboard/tenant-detail/sections/pipeline/wasm-module-field';
import {
  ALL_WAF_RULE_SETS,
  isKeyByValue,
  MAX_GRAPHQL_COMPLEXITY,
  MAX_GRAPHQL_COST_PER_COMPLEXITY,
  MAX_GRAPHQL_DEPTH,
  MAX_TOKEN_BUDGET,
  MAX_TOKEN_WINDOW_SECONDS,
  MIN_TOKEN_WINDOW_SECONDS,
} from '@/constants/pipeline';
import { usePipelineOptions } from '@/hooks/dashboard/use-pipeline-options';
import { getApiErrorMessage, uploadWasmModule } from '@/lib/api';
import type {
  AddableStagePayload,
  HeaderEntry,
  LlmDialect,
  RateLimitKeyBy,
  StageKind,
  WafRuleSet,
} from '@/types/pipeline';

type AddStageModalProps = {
  existingKinds: StageKind[];
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: AddableStagePayload) => void;
  open: boolean;
  orgSlug?: string;
  tenantSlug?: string;
};

const DEFAULT_ANOMALY_THRESHOLD = '5';
const DEFAULT_MAX_BODY_BYTES = '1048576';
const DEFAULT_MAX_REQUESTS = '100';
const DEFAULT_WINDOW_SECONDS = '60';
const DEFAULT_WASM_TIMEOUT_MS = '100';
const DEFAULT_WASM_MAX_MEMORY_BYTES = '1048576';
const DEFAULT_TOKEN_MAX = '100000';
const DEFAULT_TOKEN_WINDOW = '3600';
const DEFAULT_TOKEN_UNKNOWN_CHARGE = '1000';
const DEFAULT_GRAPHQL_MAX_DEPTH = '10';
const DEFAULT_GRAPHQL_MAX_COMPLEXITY = '1000';
const DEFAULT_GRAPHQL_COST_PER_COMPLEXITY = '0';

function isWithin(value: string, min: number, max: number) {
  const parsed = Number(value);

  return Number.isInteger(parsed) && parsed >= min && parsed <= max;
}

function toNameList(text: string) {
  return text
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean);
}

function isCompleteEntryList(entries: HeaderEntry[]) {
  return entries.every((entry) => entry.name.trim() && entry.value.trim());
}

export function AddStageModal({
  existingKinds,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
  tenantSlug,
}: AddStageModalProps) {
  const t = useTranslations('dashboard.pipelines.addStage');
  const tErrors = useTranslations('common.errors');
  const {
    addableStageKindOptions,
    llmDialectOptions,
    rateLimitKeyByOptions,
    stageKindDescription,
    wafRuleSetOptions,
  } = usePipelineOptions();
  const [wasOpen, setWasOpen] = useState(open);
  const [kind, setKind] = useState<string>('');
  const [ruleSets, setRuleSets] = useState<string[]>(ALL_WAF_RULE_SETS);
  const [anomalyThreshold, setAnomalyThreshold] = useState(DEFAULT_ANOMALY_THRESHOLD);
  const [maxBodyBytes, setMaxBodyBytes] = useState(DEFAULT_MAX_BODY_BYTES);
  const [maxRequests, setMaxRequests] = useState(DEFAULT_MAX_REQUESTS);
  const [windowSeconds, setWindowSeconds] = useState(DEFAULT_WINDOW_SECONDS);
  const [keyBy, setKeyBy] = useState<string>('IpAddress');
  const [tokensText, setTokensText] = useState('');
  const [moduleName, setModuleName] = useState('');
  const [moduleRef, setModuleRef] = useState('');
  const [uploadError, setUploadError] = useState('');
  const [wasmTimeoutMs, setWasmTimeoutMs] = useState(DEFAULT_WASM_TIMEOUT_MS);
  const [wasmMaxMemoryBytes, setWasmMaxMemoryBytes] = useState(DEFAULT_WASM_MAX_MEMORY_BYTES);
  const [tokenMax, setTokenMax] = useState(DEFAULT_TOKEN_MAX);
  const [tokenWindow, setTokenWindow] = useState(DEFAULT_TOKEN_WINDOW);
  const [tokenDialect, setTokenDialect] = useState<string>('open_ai');
  const [tokenKeyBy, setTokenKeyBy] = useState<string>('ConsumerId');
  const [tokenChargesUnknown, setTokenChargesUnknown] = useState(true);
  const [tokenUnknownCharge, setTokenUnknownCharge] = useState(DEFAULT_TOKEN_UNKNOWN_CHARGE);
  const [graphQlMaxDepth, setGraphQlMaxDepth] = useState(DEFAULT_GRAPHQL_MAX_DEPTH);
  const [graphQlMaxComplexity, setGraphQlMaxComplexity] = useState(DEFAULT_GRAPHQL_MAX_COMPLEXITY);
  const [graphQlCostPerComplexity, setGraphQlCostPerComplexity] = useState(
    DEFAULT_GRAPHQL_COST_PER_COMPLEXITY,
  );
  const [setHeaders, setSetHeaders] = useState<HeaderEntry[]>([]);
  const [removeHeadersText, setRemoveHeadersText] = useState('');
  const [setQuery, setSetQuery] = useState<HeaderEntry[]>([]);
  const [removeQueryText, setRemoveQueryText] = useState('');

  const { isPending: isUploadingModule, mutate: submitModuleUpload } = useMutation({
    mutationFn: (file: File) => {
      if (!orgSlug || !tenantSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return readAsBase64(file).then((bytecode) => uploadWasmModule(orgSlug, tenantSlug, bytecode));
    },
    onSuccess: (reference) => {
      setModuleRef(reference);
      setUploadError('');
    },
    onError: (error) => {
      setModuleRef('');
      setUploadError(getApiErrorMessage(error, t('uploadFailed')));
    },
  });

  function handleModuleSelect(file: File) {
    setModuleName(file.name);
    setModuleRef('');
    setUploadError('');
    submitModuleUpload(file);
  }

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      resetFields();
    }
  }

  const options = addableStageKindOptions.filter(
    (option) => !existingKinds.includes(option.value as StageKind),
  );
  const tokens = toNameList(tokensText);
  const removeHeaders = toNameList(removeHeadersText);
  const removeQuery = toNameList(removeQueryText);
  const isValid = isConfiguredStage();

  function isConfiguredStage() {
    switch (kind) {
      case 'Waf':
        return ruleSets.length > 0 && Number(anomalyThreshold) > 0 && Number(maxBodyBytes) > 0;
      case 'RateLimit':
        return Number(maxRequests) > 0 && Number(windowSeconds) > 0 && isKeyByValue(keyBy);
      case 'CanaryToken':
        return tokens.length > 0;
      case 'TokenRateLimit':
        // The fallback may not exceed the budget: one unreported exchange
        // spending the whole window refuses every second request, which reads
        // as broken rather than strict. The API refuses it too.
        return (
          isWithin(tokenMax, 1, MAX_TOKEN_BUDGET) &&
          isWithin(tokenWindow, MIN_TOKEN_WINDOW_SECONDS, MAX_TOKEN_WINDOW_SECONDS) &&
          isKeyByValue(tokenKeyBy) &&
          (!tokenChargesUnknown || isWithin(tokenUnknownCharge, 0, Number(tokenMax)))
        );
      case 'GraphQl':
        return (
          isWithin(graphQlMaxDepth, 1, MAX_GRAPHQL_DEPTH) &&
          isWithin(graphQlMaxComplexity, 1, MAX_GRAPHQL_COMPLEXITY) &&
          isWithin(graphQlCostPerComplexity, 0, MAX_GRAPHQL_COST_PER_COMPLEXITY)
        );
      case 'RequestTransform':
        return (
          setHeaders.length + removeHeaders.length + setQuery.length + removeQuery.length > 0 &&
          isCompleteEntryList(setHeaders) &&
          isCompleteEntryList(setQuery)
        );
      case 'ResponseTransform':
        return setHeaders.length + removeHeaders.length > 0 && isCompleteEntryList(setHeaders);
      case 'Custom':
        return Boolean(moduleRef) && Number(wasmTimeoutMs) > 0 && Number(wasmMaxMemoryBytes) > 0;
      default:
        return false;
    }
  }

  function resetFields() {
    setKind('');
    setRuleSets(ALL_WAF_RULE_SETS);
    setAnomalyThreshold(DEFAULT_ANOMALY_THRESHOLD);
    setMaxBodyBytes(DEFAULT_MAX_BODY_BYTES);
    setMaxRequests(DEFAULT_MAX_REQUESTS);
    setWindowSeconds(DEFAULT_WINDOW_SECONDS);
    setKeyBy('IpAddress');
    setTokensText('');
    setTokenMax(DEFAULT_TOKEN_MAX);
    setTokenWindow(DEFAULT_TOKEN_WINDOW);
    setTokenDialect('open_ai');
    setTokenKeyBy('ConsumerId');
    setTokenChargesUnknown(true);
    setTokenUnknownCharge(DEFAULT_TOKEN_UNKNOWN_CHARGE);
    setModuleName('');
    setModuleRef('');
    setUploadError('');
    setWasmTimeoutMs(DEFAULT_WASM_TIMEOUT_MS);
    setWasmMaxMemoryBytes(DEFAULT_WASM_MAX_MEMORY_BYTES);
    setGraphQlMaxDepth(DEFAULT_GRAPHQL_MAX_DEPTH);
    setGraphQlMaxComplexity(DEFAULT_GRAPHQL_MAX_COMPLEXITY);
    setGraphQlCostPerComplexity(DEFAULT_GRAPHQL_COST_PER_COMPLEXITY);
    setSetHeaders([]);
    setRemoveHeadersText('');
    setSetQuery([]);
    setRemoveQueryText('');
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    resetFields();
    onClose();
  }

  function handleSubmit() {
    if (!isValid) {
      return;
    }

    if (kind === 'Waf') {
      onSubmit({
        config: {
          anomalyThreshold: Number(anomalyThreshold),
          maxBodyBytes: Number(maxBodyBytes),
          ruleSets: ruleSets as WafRuleSet[],
        },
        kind: 'Waf',
      });
      return;
    }

    if (kind === 'RateLimit' && isKeyByValue(keyBy)) {
      onSubmit({
        config: {
          keyBy: keyBy as RateLimitKeyBy,
          maxRequests: Number(maxRequests),
          windowSeconds: Number(windowSeconds),
        },
        kind: 'RateLimit',
      });
      return;
    }

    if (kind === 'CanaryToken') {
      onSubmit({ config: { tokens }, kind: 'CanaryToken' });
      return;
    }

    if (kind === 'TokenRateLimit' && isKeyByValue(tokenKeyBy)) {
      onSubmit({
        config: {
          dialect: tokenDialect as LlmDialect,
          keyBy: tokenKeyBy as RateLimitKeyBy,
          maxTokens: Number(tokenMax),
          onUnknown: tokenChargesUnknown ? { charge: Number(tokenUnknownCharge) } : 'ignore',
          windowSeconds: Number(tokenWindow),
        },
        kind: 'TokenRateLimit',
      });
      return;
    }

    if (kind === 'GraphQl') {
      onSubmit({
        config: {
          costPerComplexity: Number(graphQlCostPerComplexity),
          maxComplexity: Number(graphQlMaxComplexity),
          maxDepth: Number(graphQlMaxDepth),
        },
        kind: 'GraphQl',
      });
      return;
    }

    if (kind === 'RequestTransform') {
      onSubmit({
        config: { removeHeaders, removeQuery, setHeaders, setQuery },
        kind: 'RequestTransform',
      });
      return;
    }

    if (kind === 'ResponseTransform') {
      onSubmit({ config: { removeHeaders, setHeaders }, kind: 'ResponseTransform' });
      return;
    }

    if (kind === 'Custom') {
      onSubmit({
        config: {
          maxMemoryBytes: Number(wasmMaxMemoryBytes),
          moduleRef,
          timeoutMs: Number(wasmTimeoutMs),
        },
        kind: 'Custom',
      });
    }
  }

  const hasAddableKinds = options.length > 0;

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      primaryActionLabel={hasAddableKinds ? t('submit') : t('close')}
      isPrimaryActionDisabled={hasAddableKinds && (!isValid || isSubmitting)}
      isPrimaryActionLoading={isSubmitting}
      onPrimaryAction={hasAddableKinds ? handleSubmit : handleClose}
      onSecondaryAction={handleClose}
      showCancelButton={hasAddableKinds}
      showCloseButton={false}
    >
      {hasAddableKinds ? (
        <Select
          label={t('stageType')}
          placeholder={t('stageTypePlaceholder')}
          containerClassName="mb-0"
          className="bg-cardBg"
          options={options}
          value={kind}
          hint={kind ? stageKindDescription(kind as StageKind) : undefined}
          disabled={isSubmitting}
          onChange={setKind}
        />
      ) : (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-borderGray px-4 py-8 text-center">
          <span className="material-symbols-rounded text-2xl! text-primary" aria-hidden>
            task_alt
          </span>
          <p className="text-sm font-semibold text-white">{t('allAdded')}</p>
          <p className="text-xs text-textGray">{t('allAddedHint')}</p>
        </div>
      )}

      {kind === 'Waf' ? (
        <>
          <MultiSelect
            label={t('ruleSets')}
            placeholder={t('ruleSetsPlaceholder')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={wafRuleSetOptions}
            value={ruleSets}
            disabled={isSubmitting}
            onChange={setRuleSets}
          />
          <Input
            type="number"
            label={t('anomalyThreshold')}
            hint={t('anomalyThresholdHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={anomalyThreshold}
            onChange={(event) => setAnomalyThreshold(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('maxBodyBytes')}
            hint={t('maxBodyBytesHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={maxBodyBytes}
            onChange={(event) => setMaxBodyBytes(event.target.value)}
            disabled={isSubmitting}
          />
        </>
      ) : null}

      {kind === 'RateLimit' ? (
        <>
          <Input
            type="number"
            label={t('maxRequests')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={maxRequests}
            onChange={(event) => setMaxRequests(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('window')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={windowSeconds}
            onChange={(event) => setWindowSeconds(event.target.value)}
            disabled={isSubmitting}
          />
          <Select
            label={t('limitBy')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={rateLimitKeyByOptions}
            value={keyBy}
            disabled={isSubmitting}
            onChange={setKeyBy}
          />
        </>
      ) : null}

      {kind === 'CanaryToken' ? (
        <Input
          label={t('decoyTokens')}
          placeholder={t('decoyTokensPlaceholder')}
          hint={t('decoyTokensHint')}
          containerClassName="mb-0"
          className="bg-cardBg"
          value={tokensText}
          onChange={(event) => setTokensText(event.target.value)}
          disabled={isSubmitting}
        />
      ) : null}

      {kind === 'TokenRateLimit' ? (
        <>
          <Input
            type="number"
            label={t('tokenBudget')}
            hint={t('tokenBudgetHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={tokenMax}
            onChange={(event) => setTokenMax(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('window')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={tokenWindow}
            onChange={(event) => setTokenWindow(event.target.value)}
            disabled={isSubmitting}
          />
          <Select
            label={t('budgetPer')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={rateLimitKeyByOptions}
            value={tokenKeyBy}
            disabled={isSubmitting}
            onChange={setTokenKeyBy}
          />
          <Select
            label={t('provider')}
            hint={t('providerHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={llmDialectOptions}
            value={tokenDialect}
            disabled={isSubmitting}
            onChange={setTokenDialect}
          />
          <div className="flex flex-col gap-2">
            <Checkbox
              label={t('chargeUnknown')}
              checked={tokenChargesUnknown}
              disabled={isSubmitting}
              onChange={(event) => setTokenChargesUnknown(event.target.checked)}
            />
            <p className="pl-6 text-xs text-textGray">{t('unknownUsageHint')}</p>
          </div>
          {tokenChargesUnknown ? (
            <Input
              type="number"
              label={t('unknownCharge')}
              hint={t('unknownChargeHint')}
              containerClassName="mb-0"
              className="bg-cardBg"
              value={tokenUnknownCharge}
              onChange={(event) => setTokenUnknownCharge(event.target.value)}
              disabled={isSubmitting}
            />
          ) : null}
        </>
      ) : null}

      {kind === 'GraphQl' ? (
        <>
          <Input
            type="number"
            label={t('maxDepth')}
            hint={t('maxDepthHint', { max: MAX_GRAPHQL_DEPTH })}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={graphQlMaxDepth}
            onChange={(event) => setGraphQlMaxDepth(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('maxComplexity')}
            hint={t('maxComplexityHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={graphQlMaxComplexity}
            onChange={(event) => setGraphQlMaxComplexity(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('costPerComplexity')}
            hint={t('costPerComplexityHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={graphQlCostPerComplexity}
            onChange={(event) => setGraphQlCostPerComplexity(event.target.value)}
            disabled={isSubmitting}
          />
        </>
      ) : null}

      {kind === 'RequestTransform' || kind === 'ResponseTransform' ? (
        <>
          <HeaderEntriesField
            entries={setHeaders}
            hint={t('secretHint', {
              fileRef: '{file://tenants/<tenant id>/name}',
              vaultRef: '{vault://secret/data/tenants/<tenant id>/name#key}',
            })}
            isDisabled={isSubmitting}
            label={t('setHeaders')}
            namePlaceholder="X-Api-Key"
            valuePlaceholder="{vault://secret/data/backend#api_key}"
            onChange={setSetHeaders}
          />
          <Input
            label={t('removeHeaders')}
            placeholder="Server, X-Powered-By"
            hint={t('commaSeparated')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={removeHeadersText}
            onChange={(event) => setRemoveHeadersText(event.target.value)}
            disabled={isSubmitting}
          />
        </>
      ) : null}

      {kind === 'RequestTransform' ? (
        <>
          <HeaderEntriesField
            entries={setQuery}
            isDisabled={isSubmitting}
            label={t('setQuery')}
            namePlaceholder="version"
            valuePlaceholder="v2"
            onChange={setSetQuery}
          />
          <Input
            label={t('removeQuery')}
            placeholder="debug, trace"
            hint={t('commaSeparated')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={removeQueryText}
            onChange={(event) => setRemoveQueryText(event.target.value)}
            disabled={isSubmitting}
          />
        </>
      ) : null}

      {kind === 'Custom' ? (
        <>
          <WasmModuleField
            error={uploadError}
            fileName={moduleName}
            isDisabled={isSubmitting}
            isUploading={isUploadingModule}
            moduleRef={moduleRef}
            onSelect={handleModuleSelect}
          />
          <Input
            type="number"
            label={t('timeout')}
            hint={t('timeoutHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={wasmTimeoutMs}
            onChange={(event) => setWasmTimeoutMs(event.target.value)}
            disabled={isSubmitting}
          />
          <Input
            type="number"
            label={t('maxMemory')}
            hint={t('maxMemoryHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            value={wasmMaxMemoryBytes}
            onChange={(event) => setWasmMaxMemoryBytes(event.target.value)}
            disabled={isSubmitting}
          />
        </>
      ) : null}
    </Modal>
  );
}

/**
 * Reads a file as standard, padded base64 - the encoding the upload endpoint
 * expects. `FileReader` hands back a `data:` URL, so the prefix comes off.
 */
function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onerror = () => reject(new Error('Could not read the selected file.'));
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      resolve(result.slice(result.indexOf(',') + 1));
    };

    reader.readAsDataURL(file);
  });
}
