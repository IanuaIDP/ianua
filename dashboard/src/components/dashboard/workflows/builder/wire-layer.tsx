'use client';

import type { SceneWire } from '@/components/dashboard/workflows/builder/canvas-scene';
import { cn } from '@/utils/cn';

const LEVEL_STROKES: Record<string, string> = {
  confidential: 'stroke-orange',
  restricted: 'stroke-error',
};

type WireLayerProps = {
  draftPath: string | null;
  levelOf: (wire: SceneWire) => string;
  onSelect: (wire: SceneWire) => void;
  ranIds: Set<string>;
  selectedId: string | null;
  wires: SceneWire[];
};

/** Every arrow: one wide invisible line to click on, and the one that shows. */
export function WireLayer({
  draftPath,
  levelOf,
  onSelect,
  ranIds,
  selectedId,
  wires,
}: WireLayerProps) {
  return (
    <svg
      aria-hidden="true"
      className="pointer-events-none absolute left-0 top-0 size-px overflow-visible"
    >
      {wires.map((wire) => (
        <g key={wire.id}>
          <path
            d={wire.path}
            data-wire-id={wire.id}
            fill="none"
            stroke="transparent"
            strokeWidth={16}
            className="cursor-pointer"
            style={{ pointerEvents: 'stroke' }}
            onClick={() => onSelect(wire)}
          />
          <path
            d={wire.path}
            fill="none"
            strokeLinecap="round"
            strokeWidth={selectedId === wire.id ? 3 : 2}
            className={cn(
              LEVEL_STROKES[levelOf(wire)] ?? 'stroke-[#4c4f48]',
              ranIds.has(wire.id) && 'stroke-green',
              selectedId === wire.id && 'stroke-primary',
            )}
          />
        </g>
      ))}
      {draftPath ? (
        <path
          d={draftPath}
          fill="none"
          strokeDasharray="5 5"
          strokeWidth={2}
          className="stroke-primary"
        />
      ) : null}
    </svg>
  );
}
