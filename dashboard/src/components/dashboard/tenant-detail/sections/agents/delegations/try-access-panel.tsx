'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation } from '@tanstack/react-query';

import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { getApiErrorMessage } from '@/lib/api';
import { probeGateway, type GatewayProbeResult } from '@/lib/api/services/gateway-probe';

type TryAccessPanelProps = {
  hosts: string[];
  token: string;
};

const METHOD_OPTIONS = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'PUT', value: 'PUT' },
  { label: 'PATCH', value: 'PATCH' },
  { label: 'DELETE', value: 'DELETE' },
];

/// Sends one real request with the token that was just minted.
///
/// Everything before this is a description of what an agent will be allowed to
/// do. This is the only place someone finds out whether it is true — and the
/// refusals are the interesting half: a tool outside the grant, a purpose the
/// token did not declare, a delegation revoked a second ago. Reading "403 —
/// caller's delegation does not grant this tool" is worth more than any
/// explanation of the model.
export function TryAccessPanel({ hosts, token }: TryAccessPanelProps) {
  const t = useTranslations('dashboard.delegations.tryAccess');
  const [host, setHost] = useState(hosts[0] ?? '');
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/');
  const [result, setResult] = useState<GatewayProbeResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const { orgSlug, tenantSlug } = useAgentRouteParams();

  const { isPending, mutate: send } = useMutation({
    mutationFn: () =>
      probeGateway({ host, method, orgSlug: orgSlug ?? '', path, tenantSlug, token }),
    onError: (error) => {
      setResult(null);
      setFailure(getApiErrorMessage(error, t('unreachable')));
    },
    onSuccess: (probe) => {
      setFailure(null);
      setResult(probe);
    },
  });

  const allowed = result ? result.status < 400 : false;

  return (
    <div className="mt-4 rounded-lg border border-borderGray p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray">
        {t('title')}
      </p>
      <p className="mt-1 text-[10px] leading-snug text-textGray">{t('description')}</p>

      <div className="mt-2.5 flex flex-col gap-2">
        {hosts.length > 1 ? (
          <Select
            label={t('gateway')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={hosts.map((value) => ({ label: value, value }))}
            value={host}
            disabled={isPending}
            onChange={setHost}
          />
        ) : null}

        <div className="grid grid-cols-[auto_1fr] gap-2">
          <Select
            label={t('method')}
            containerClassName="mb-0 w-28"
            className="bg-cardBg"
            options={METHOD_OPTIONS}
            value={method}
            disabled={isPending}
            onChange={setMethod}
          />
          <Input
            label={t('path')}
            placeholder="/reports"
            containerClassName="mb-0"
            className="bg-cardBg"
            value={path}
            disabled={isPending}
            onChange={(event) => setPath(event.target.value)}
          />
        </div>

        <button
          type="button"
          disabled={isPending || !host || !path}
          onClick={() => send()}
          className="self-start rounded-md bg-focus px-3 py-1.5 text-[10px] font-semibold text-white transition hover:bg-hoverBgPurple disabled:opacity-40"
        >
          {isPending ? t('sending') : t('send')}
        </button>
      </div>

      {failure ? (
        <p className="mt-3 rounded-lg border border-error bg-error/10 px-3 py-2 text-[10px] font-medium text-error">
          {failure}
        </p>
      ) : null}

      {result ? (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 ${
            allowed ? 'border-primary/50 bg-primary/10' : 'border-orange/50 bg-orange/10'
          }`}
        >
          <p className={`text-xs font-semibold ${allowed ? 'text-primary' : 'text-orange'}`}>
            {allowed ? t('allowed') : t('refused')} · {result.status} ·{' '}
            {t('duration', { ms: result.durationMs })}
          </p>
          {result.reason ? (
            <p className="mt-1 text-[10px] leading-snug text-white">{result.reason}</p>
          ) : null}
          {result.body ? (
            <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] leading-relaxed text-textGray">
              {result.body}
              {result.truncated ? '\n…' : ''}
            </pre>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
