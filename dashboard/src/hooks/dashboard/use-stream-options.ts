import { useTranslations } from 'next-intl';

import type { MultiSelectOption } from '@/components/ui/MultiSelect';
import {
  ALL_SIGNAL_TYPES_VALUE,
  STREAM_DELIVERY_METHODS,
  STREAM_REAL_SIGNAL_TYPE_IDS,
} from '@/constants/stream';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SelectOption } from '@/types/dashboard';
import type { DeliveryMethod } from '@/types/stream';
import { formatStatusLabel } from '@/utils/format-status-label';

/** Delivery methods and signal types worded in the current language. */
export function useStreamOptions() {
  const t = useTranslations('dashboard.streams');
  const tSignalTypes = useLooseTranslations('dashboard.streams.signalTypes');

  function signalTypeLabel(signalType: string) {
    return tSignalTypes.has(signalType) ? tSignalTypes(signalType) : formatStatusLabel(signalType);
  }

  const deliveryMethodOptions: (SelectOption & { value: DeliveryMethod })[] =
    STREAM_DELIVERY_METHODS.map((method) => ({
      label: t(`deliveryMethods.${method}`),
      value: method,
    }));
  const signalTypeOptions: MultiSelectOption[] = [
    { label: t('allSignalTypes'), value: ALL_SIGNAL_TYPES_VALUE },
    ...STREAM_REAL_SIGNAL_TYPE_IDS.map((id) => ({ label: signalTypeLabel(id), value: id })),
  ];

  return {
    deliveryMethodLabel: (method: DeliveryMethod) => t(`deliveryMethods.${method}`),
    deliveryMethodOptions,
    signalTypeLabel,
    signalTypeOptions,
  };
}
