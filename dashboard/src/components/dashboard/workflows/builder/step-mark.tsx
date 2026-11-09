'use client';

import Image from 'next/image';

import { COMPANY_INTEGRATION } from '@/components/dashboard/workflows/builder/constants';
import type { WorkflowNode, WorkflowTrigger } from '@/types/workflow-graph';
import type { WorkflowIntegration } from '@/types/workflows';
import { cn } from '@/utils/cn';

const KIND_ICONS: Record<WorkflowNode['kind'], string> = {
  action: 'extension',
  agent_run: 'smart_toy',
  approval: 'person_check',
  code: 'code_blocks',
  condition: 'call_split',
  guardrail: 'shield',
  loop: 'repeat',
  transform: 'data_object',
  wait: 'hourglass_top',
};

const KIND_TONES: Partial<Record<WorkflowNode['kind'], string>> = {
  agent_run: 'bg-primary/15 text-primary',
  approval: 'bg-orange/15 text-orange',
  code: 'bg-focus/15 text-focus',
  guardrail: 'bg-green/15 text-green',
};

const TRIGGER_ICONS: Record<WorkflowTrigger['type'], string> = {
  before: 'policy',
  event: 'bolt',
  manual: 'touch_app',
  schedule: 'schedule',
  service: 'extension',
  webhook: 'webhook',
};

type StepMarkProps = {
  className?: string;
  integration?: WorkflowIntegration | null;
  node?: WorkflowNode | null;
  size?: 'md' | 'sm';
  trigger?: WorkflowTrigger;
};

/** A step's mark: the integration's picture on its brand colour, or a built-in icon. */
export function StepMark({ className, integration, node, size = 'md', trigger }: StepMarkProps) {
  const sizeClassName = size === 'md' ? 'size-9 rounded-lg' : 'size-7 rounded-md';

  if (node?.kind === 'action' && integration) {
    const icon = integration.key === COMPANY_INTEGRATION ? 'shield_person' : KIND_ICONS.action;

    return (
      <span
        className={cn('flex shrink-0 items-center justify-center', sizeClassName, className)}
        style={{ backgroundColor: integration.brand }}
        aria-hidden="true"
      >
        {integration.picture ? (
          <Image
            alt=""
            className="brightness-0 invert"
            height={20}
            src={`/api/files/integrations/${encodeURIComponent(integration.key)}/picture.svg`}
            unoptimized
            width={20}
          />
        ) : (
          <span className="material-symbols-rounded text-white">{icon}</span>
        )}
      </span>
    );
  }

  const icon = trigger ? TRIGGER_ICONS[trigger.type] : KIND_ICONS[node?.kind ?? 'action'];
  const tone = node ? KIND_TONES[node.kind] : undefined;

  return (
    <span
      className={cn(
        'flex shrink-0 items-center justify-center',
        sizeClassName,
        tone ?? 'bg-surfaceChip text-textGray',
        className,
      )}
      aria-hidden="true"
    >
      <span className="material-symbols-rounded">{icon}</span>
    </span>
  );
}
