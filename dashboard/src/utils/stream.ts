import { ALL_SIGNAL_TYPES_VALUE, STREAM_REAL_SIGNAL_TYPE_VALUES } from '@/constants/stream';
import type { StreamFormInput } from '@/schemas/stream-schemas';
import type { Stream } from '@/types/stream';

export function toStreamFormValues(stream: Stream): StreamFormInput {
  return {
    deliveryMethod: stream.deliveryMethod,
    endpoint: stream.endpoint,
    signalTypes:
      stream.signalTypes.length >= STREAM_REAL_SIGNAL_TYPE_VALUES.length
        ? [ALL_SIGNAL_TYPES_VALUE, ...STREAM_REAL_SIGNAL_TYPE_VALUES]
        : stream.signalTypes,
  };
}
