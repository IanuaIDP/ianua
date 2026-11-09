import { useTranslations } from 'next-intl';

import { STREAM_POLICIES, STREAM_PROTOCOLS } from '@/constants/stream-route';
import type { SelectOption } from '@/types/dashboard';
import type { StreamPolicy, StreamProtocol } from '@/types/stream-route';

/** The protocols and policies of a port, worded in the current language. */
export function useStreamRouteOptions() {
  const t = useTranslations('dashboard.ports');

  const protocolOptions: (SelectOption & { value: StreamProtocol })[] = STREAM_PROTOCOLS.map(
    (protocol) => ({ label: t(`protocols.${protocol}`), value: protocol }),
  );
  const policyOptions: (SelectOption & { value: StreamPolicy })[] = STREAM_POLICIES.map(
    (policy) => ({ label: t(`policies.${policy}`), value: policy }),
  );

  return {
    policyOptions,
    protocolHint: (protocol: StreamProtocol) => t(`protocolHints.${protocol}`),
    protocolLabel: (protocol: StreamProtocol) => t(`protocolLabels.${protocol}`),
    protocolOptions,
  };
}
