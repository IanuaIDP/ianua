'use client';

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type PointerEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import { useTranslations } from 'next-intl';

import {
  buildCanvasScene,
  type SceneCard,
  type SceneWire,
} from '@/components/dashboard/workflows/builder/canvas-scene';
import {
  CARD_HEIGHT,
  CARD_WIDTH,
  MAX_ZOOM,
  MIN_ZOOM,
  PORT_OFFSET_Y,
  TRIGGER_KEY,
} from '@/components/dashboard/workflows/builder/constants';
import { getStepPorts, getStepsInOrder } from '@/components/dashboard/workflows/builder/graph';
import { StepCard, type StepFlag } from '@/components/dashboard/workflows/builder/step-card';
import type { BuilderSelection } from '@/components/dashboard/workflows/builder/use-working-copy';
import { WireLayer } from '@/components/dashboard/workflows/builder/wire-layer';
import type {
  Point,
  StepPlacement,
  WorkingCopy,
} from '@/components/dashboard/workflows/builder/working-copy';
import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import type { WorkflowEdge, WorkflowNode, WorkflowPort } from '@/types/workflow-graph';
import type { StepState } from '@/types/workflows';
import { cn } from '@/utils/cn';

export const STEP_DRAG_TYPE = 'application/x-ianua-step';

export type CanvasEditing = {
  onAddStep: (placement: StepPlacement) => void;
  onConnect: (edge: WorkflowEdge) => void;
  onDropStep: (data: string, point: Point) => void;
  onMove: (key: string, point: Point) => void;
  onMoveEnd: (key: string, moved: boolean) => void;
  onMoveStart: () => void;
};

type WorkflowCanvasProps = {
  copy: WorkingCopy;
  describeStep: (node: WorkflowNode | null) => { line: string; mark: ReactNode; title: string };
  editing?: CanvasEditing;
  flagOf?: (key: string) => StepFlag;
  levelOf?: (from: string) => string;
  onSelect: (selection: BuilderSelection) => void;
  runSteps?: Map<string, StepState>;
  selection: BuilderSelection;
  /** Filled with a function giving the board point at the middle of the view. */
  viewCentreRef?: RefObject<(() => Point) | null>;
};

type View = { x: number; y: number; zoom: number };

type Gesture =
  | { kind: 'move'; card: SceneCard; moved: boolean; offset: Point }
  | { kind: 'pan'; moved: boolean; originX: number; originY: number; x: number; y: number }
  | { from: string; kind: 'wire'; port: WorkflowPort };

const FIT_PADDING = 60;

function getWireId(edge: WorkflowEdge) {
  return `${edge.from}/${edge.port}/${edge.to}`;
}

function getRanWireIds(wires: SceneWire[], runSteps: Map<string, StepState> | undefined) {
  const ran = new Set<string>();

  if (!runSteps) {
    return ran;
  }

  for (const wire of wires) {
    const to = runSteps.get(wire.edge.to);

    if (wire.isImplied) {
      if (to && to.phase !== 'waiting' && to.phase !== 'skipped') {
        ran.add(wire.id);
      }

      continue;
    }

    if (runSteps.get(wire.edge.from)?.port === wire.edge.port) {
      ran.add(wire.id);
    }
  }

  return ran;
}

export function WorkflowCanvas({
  copy,
  describeStep,
  editing,
  flagOf,
  levelOf,
  onSelect,
  runSteps,
  selection,
  viewCentreRef,
}: WorkflowCanvasProps) {
  const t = useTranslations('dashboard.workflowBuilder.canvas');
  const root = useRef<HTMLDivElement>(null);
  const gesture = useRef<Gesture | null>(null);
  const [view, setView] = useState<View>({ x: 40, y: 40, zoom: 1 });
  const [draftPath, setDraftPath] = useState<string | null>(null);
  const scene = useMemo(() => buildCanvasScene(copy), [copy]);
  const order = useMemo(() => getStepsInOrder(copy.nodes, copy.edges), [copy.edges, copy.nodes]);
  const ranIds = useMemo(() => getRanWireIds(scene.wires, runSteps), [runSteps, scene.wires]);
  const selectedWireId = selection?.type === 'wire' ? getWireId(selection.edge) : null;

  const fit = useCallback(() => {
    const element = root.current;

    if (!element) {
      return;
    }

    const width = scene.bounds.right - scene.bounds.left + FIT_PADDING * 2;
    const height = scene.bounds.bottom - scene.bounds.top + FIT_PADDING * 2;
    const zoom = Math.max(
      MIN_ZOOM,
      Math.min(1, element.clientWidth / width, element.clientHeight / height),
    );

    setView({
      x: (FIT_PADDING - scene.bounds.left) * zoom,
      y: (FIT_PADDING - scene.bounds.top) * zoom,
      zoom,
    });
  }, [scene.bounds]);

  useLayoutEffect(() => {
    fit();
    // Fits once per copy opened; moving a step must leave the view alone.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toBoardPoint = useCallback(
    (clientX: number, clientY: number): Point => {
      const rect = root.current?.getBoundingClientRect();

      return {
        x: (clientX - (rect?.left ?? 0) - view.x) / view.zoom,
        y: (clientY - (rect?.top ?? 0) - view.y) / view.zoom,
      };
    },
    [view],
  );

  useEffect(() => {
    if (viewCentreRef) {
      viewCentreRef.current = () => {
        const element = root.current;

        return {
          x: ((element?.clientWidth ?? 0) / 2 - view.x) / view.zoom - CARD_WIDTH / 2,
          y: ((element?.clientHeight ?? 0) / 2 - view.y) / view.zoom - CARD_HEIGHT / 2,
        };
      };
    }
  }, [view, viewCentreRef]);

  useEffect(() => {
    const element = root.current;

    if (!element) {
      return;
    }

    function handleWheel(event: WheelEvent) {
      event.preventDefault();

      if (!(event.ctrlKey || event.metaKey)) {
        setView((current) => ({
          ...current,
          x: current.x - event.deltaX,
          y: current.y - event.deltaY,
        }));

        return;
      }

      const rect = element?.getBoundingClientRect();
      const cursorX = event.clientX - (rect?.left ?? 0);
      const cursorY = event.clientY - (rect?.top ?? 0);

      setView((current) => {
        const zoom = Math.min(
          MAX_ZOOM,
          Math.max(MIN_ZOOM, current.zoom * (event.deltaY > 0 ? 0.9 : 1.1)),
        );
        const scale = zoom / current.zoom;

        return {
          x: cursorX - (cursorX - current.x) * scale,
          y: cursorY - (cursorY - current.y) * scale,
          zoom,
        };
      });
    }

    element.addEventListener('wheel', handleWheel, { passive: false });

    return () => element.removeEventListener('wheel', handleWheel);
  }, []);

  function changeZoom(delta: number) {
    setView((current) => ({
      ...current,
      zoom: Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round((current.zoom + delta) * 10) / 10)),
    }));
  }

  function startPan(event: PointerEvent<HTMLDivElement>) {
    gesture.current = {
      kind: 'pan',
      moved: false,
      originX: view.x,
      originY: view.y,
      x: event.clientX,
      y: event.clientY,
    };
  }

  function startCard(event: PointerEvent<HTMLDivElement>, cardElement: Element) {
    const key = cardElement.getAttribute('data-card-key') ?? '';

    onSelect(key === TRIGGER_KEY ? { type: 'trigger' } : { key, type: 'step' });

    const card = [...scene.cards, ...scene.loops].find((item) => item.key === key);

    if (!editing || !card || card.node === null || card.inLoop) {
      return;
    }

    const point = toBoardPoint(event.clientX, event.clientY);

    editing.onMoveStart();
    gesture.current = {
      card,
      kind: 'move',
      moved: false,
      offset: { x: point.x - card.x, y: point.y - card.y },
    };
  }

  function handlePointerDown(event: PointerEvent<HTMLDivElement>) {
    if (event.button !== 0) {
      return;
    }

    const target = event.target as Element;

    if (target.closest('[data-add-button]') || target.closest('[data-zoom-controls]')) {
      return;
    }

    const port = target.closest('[data-out-port]');
    const cardElement = target.closest('[data-card-key]');

    if (port && cardElement && editing) {
      gesture.current = {
        from: cardElement.getAttribute('data-card-key') ?? '',
        kind: 'wire',
        port: port.getAttribute('data-out-port') as WorkflowPort,
      };
    } else if (cardElement) {
      startCard(event, cardElement);
    } else if (target.closest('[data-wire-id]')) {
      return;
    } else {
      startPan(event);
    }

    root.current?.setPointerCapture(event.pointerId);
  }

  function handlePointerMove(event: PointerEvent<HTMLDivElement>) {
    const current = gesture.current;

    if (!current) {
      return;
    }

    if (current.kind === 'pan') {
      const dx = event.clientX - current.x;
      const dy = event.clientY - current.y;

      current.moved = current.moved || Math.abs(dx) + Math.abs(dy) > 3;
      setView((previous) => ({ ...previous, x: current.originX + dx, y: current.originY + dy }));

      return;
    }

    const point = toBoardPoint(event.clientX, event.clientY);

    if (current.kind === 'move') {
      current.moved = true;
      editing?.onMove(current.card.key, {
        x: point.x - current.offset.x,
        y: point.y - current.offset.y,
      });

      return;
    }

    const from = scene.cards.find((card) => card.key === current.from);

    if (from) {
      const startX = from.x + from.width + 4;
      const startY = from.y + PORT_OFFSET_Y[current.port];

      setDraftPath(`M${startX},${startY} L${point.x},${point.y}`);
    }
  }

  function endWire(event: PointerEvent<HTMLDivElement>, from: string, port: WorkflowPort) {
    setDraftPath(null);

    const target = document
      .elementFromPoint(event.clientX, event.clientY)
      ?.closest('[data-card-key]')
      ?.getAttribute('data-card-key');

    if (target && target !== TRIGGER_KEY && target !== from) {
      editing?.onConnect({ from, port, to: target });
    }
  }

  function handlePointerUp(event: PointerEvent<HTMLDivElement>) {
    const current = gesture.current;

    gesture.current = null;

    if (!current) {
      return;
    }

    if (current.kind === 'pan' && !current.moved) {
      onSelect(null);
    }

    if (current.kind === 'move') {
      editing?.onMoveEnd(current.card.key, current.moved);
    }

    if (current.kind === 'wire') {
      endWire(event, current.from, current.port);
    }
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    const data = event.dataTransfer.getData(STEP_DRAG_TYPE);

    if (data && editing) {
      event.preventDefault();
      editing.onDropStep(data, toBoardPoint(event.clientX, event.clientY));
    }
  }

  function handleSelectWire(wire: SceneWire) {
    onSelect({ edge: wire.edge, isImplied: wire.isImplied, type: 'wire' });
  }

  function getEdgesOf(card: SceneCard) {
    const loop = copy.nodes.find((node) => node.key === card.inLoop);

    return loop?.kind === 'loop' ? loop.steps.edges : copy.edges;
  }

  function renderCard(card: SceneCard) {
    const text = describeStep(card.node);
    const ports = card.node ? getStepPorts(card.node) : (['next'] as WorkflowPort[]);
    const isTrigger = card.node === null;
    const addable = !editing
      ? []
      : ports.filter(
          (port) =>
            isTrigger ||
            !getEdgesOf(card).some((edge) => edge.from === card.key && edge.port === port),
        );
    const state = runSteps?.get(card.key) ?? null;
    const number = isTrigger ? null : order.findIndex((node) => node.key === card.key) + 1;

    return (
      <StepCard
        key={card.key}
        addablePorts={addable}
        cardKey={card.key}
        flag={flagOf?.(card.key) ?? null}
        hasInPort={!isTrigger}
        isDimmed={state?.phase === 'skipped' || state?.phase === 'abandoned'}
        isSelected={
          (isTrigger && selection?.type === 'trigger') ||
          (selection?.type === 'step' && selection.key === card.key)
        }
        line={text.line}
        mark={text.mark}
        number={number && number > 0 ? number : null}
        onAddAfter={editing ? (port) => editing.onAddStep({ after: card.key, port }) : undefined}
        onSelect={() => onSelect(isTrigger ? { type: 'trigger' } : { key: card.key, type: 'step' })}
        outPorts={isTrigger ? [] : ports}
        showPorts={Boolean(editing)}
        state={state}
        title={text.title}
        x={card.x}
        y={card.y}
      />
    );
  }

  function renderLoop(loop: SceneCard) {
    const text = describeStep(loop.node);
    const isSelected = selection?.type === 'step' && selection.key === loop.key;

    return (
      <div
        key={loop.key}
        data-card-key={loop.key}
        role="button"
        tabIndex={0}
        aria-pressed={isSelected}
        aria-label={text.title}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onSelect({ key: loop.key, type: 'step' });
          }
        }}
        className={cn(
          'absolute rounded-lg border border-dashed bg-cardBg/60',
          isSelected ? 'border-primary' : 'border-menuHover',
        )}
        style={{ height: loop.height, left: loop.x, top: loop.y, width: loop.width }}
      >
        <div className="flex items-center gap-2 px-3 py-3">
          {text.mark}
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-white">{text.title}</p>
            <p className="truncate text-xs text-textGray">{text.line}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={root}
      className="relative min-h-0 flex-1 cursor-grab touch-none overflow-hidden"
      style={{
        backgroundColor: 'var(--background)',
        backgroundImage: 'radial-gradient(var(--text-border-gray) 1.2px, transparent 1.2px)',
        backgroundPosition: `${view.x}px ${view.y}px`,
        backgroundSize: `${20 * view.zoom}px ${20 * view.zoom}px`,
      }}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerUp}
      onDragOver={(event) => {
        if (editing) {
          event.preventDefault();
        }
      }}
      onDrop={handleDrop}
    >
      <div
        className="absolute left-0 top-0 size-0"
        style={{
          transform: `translate(${view.x}px, ${view.y}px) scale(${view.zoom})`,
          transformOrigin: '0 0',
        }}
      >
        {scene.loops.map(renderLoop)}
        <WireLayer
          draftPath={draftPath}
          levelOf={(wire) => levelOf?.(wire.edge.from) ?? 'public'}
          onSelect={handleSelectWire}
          ranIds={ranIds}
          selectedId={selectedWireId}
          wires={scene.wires}
        />
        {scene.wires
          .filter((wire) => wire.edge.port !== 'next')
          .map((wire) => (
            <span
              key={wire.id}
              className={cn(
                'pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 rounded-full px-2 py-0.5 text-[11px] font-semibold',
                wire.edge.port === 'when_true'
                  ? 'bg-primary/15 text-primary'
                  : 'bg-orange/15 text-orange',
              )}
              style={{ left: wire.middle.x, top: wire.middle.y }}
            >
              {wire.edge.port === 'when_true' ? t('yes') : t('no')}
            </span>
          ))}
        {scene.cards.map(renderCard)}
        {editing && selection?.type === 'wire'
          ? scene.wires
              .filter((wire) => wire.id === selectedWireId)
              .map((wire) => (
                <button
                  key={wire.id}
                  type="button"
                  data-add-button
                  aria-label={t('addOnArrow')}
                  title={t('addOnArrow')}
                  onClick={() =>
                    editing.onAddStep({
                      after: wire.edge.from,
                      port: wire.edge.port,
                      to: wire.edge.to,
                    })
                  }
                  className="absolute flex size-6.5 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full bg-primary text-black"
                  style={{
                    left: wire.middle.x,
                    top: wire.middle.y + (wire.edge.port === 'next' ? 0 : 22),
                  }}
                >
                  <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                    add
                  </span>
                </button>
              ))
          : null}
      </div>

      <div
        data-zoom-controls
        className="absolute bottom-3.5 right-3.5 z-10 flex items-center gap-0.5 rounded-lg bg-surfaceRaised p-1"
      >
        <ZoomButton icon="remove" label={t('zoomOut')} onClick={() => changeZoom(-0.1)} />
        <span className="min-w-11 text-center text-xs text-textGray">
          {Math.round(view.zoom * 100)}%
        </span>
        <ZoomButton icon="add" label={t('zoomIn')} onClick={() => changeZoom(0.1)} />
        <ZoomButton icon="fit_screen" label={t('fit')} onClick={fit} />
      </div>
    </div>
  );
}

function ZoomButton({
  icon,
  label,
  onClick,
}: {
  icon: string;
  label: string;
  onClick: () => void;
}) {
  return (
    <FloatingTooltip content={label}>
      <button
        type="button"
        aria-label={label}
        onClick={onClick}
        className="flex size-7.5 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
      >
        <span className="material-symbols-rounded text-lg!" aria-hidden="true">
          {icon}
        </span>
      </button>
    </FloatingTooltip>
  );
}
