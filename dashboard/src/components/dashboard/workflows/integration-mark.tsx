import Image from 'next/image';

import type { WorkflowIntegration } from '@/types/workflows';

type IntegrationMarkProps = {
  /** The name to show when the integration has no picture. */
  fallbackIcon?: string;
  integration: Pick<WorkflowIntegration, 'brand' | 'icon' | 'key' | 'picture'>;
};

/**
 * An integration's picture on its brand colour. A picture is always drawn as an
 * image, so an SVG can never run anything; a built-in step has no picture and
 * uses a dashboard icon instead.
 */
export function IntegrationMark({ fallbackIcon = 'extension', integration }: IntegrationMarkProps) {
  return (
    <span
      className="flex size-7 shrink-0 items-center justify-center rounded-md"
      style={{ backgroundColor: integration.brand }}
    >
      {integration.picture ? (
        <Image
          alt=""
          className="brightness-0 invert"
          height={16}
          src={`/api/files/integrations/${encodeURIComponent(integration.key)}/picture.svg`}
          unoptimized
          width={16}
        />
      ) : (
        <span className="material-symbols-rounded text-base! text-white" aria-hidden>
          {fallbackIcon}
        </span>
      )}
    </span>
  );
}
