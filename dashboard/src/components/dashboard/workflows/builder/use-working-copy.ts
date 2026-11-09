'use client';

import { create } from 'zustand';

import type { SavedCopy } from '@/components/dashboard/workflows/builder/draft-saving';
import type { DraftStash } from '@/components/dashboard/workflows/builder/draft-stash';
import {
  DEFAULT_RUN_LIMIT_SECONDS,
  MAX_ARROWS,
} from '@/components/dashboard/workflows/builder/constants';
import {
  addApprovalBefore,
  addStep,
  canConnectSteps,
  connectSteps,
  disconnectSteps,
  findStep,
  isExistingEdge,
  makeNodeKey,
  moveStep,
  removeStep,
  tidyWorkingCopy,
  toWorkingCopy,
  updateStep,
  type Point,
  type StepPlacement,
  type WorkingCopy,
} from '@/components/dashboard/workflows/builder/working-copy';
import type {
  WorkflowApprovalStep,
  WorkflowEdge,
  WorkflowNode,
  WorkflowStep,
} from '@/types/workflow-graph';
import type { Workflow } from '@/types/workflows';

export type BuilderSelection =
  | { type: 'step'; key: string }
  | { type: 'trigger' }
  | { edge: WorkflowEdge; isImplied: boolean; type: 'wire' }
  | null;

export type BuilderPanel = 'settings' | 'touches' | 'versions';

export type OutsideChange =
  { kind: 'latest'; latest: Workflow } | { kind: 'stash'; stash: DraftStash };

export type SaveStatus = 'failed' | 'idle' | 'pending' | 'saving';

type NewStepDraft = { fallbackKey: string; name: string; step: WorkflowStep };

type WorkingCopyState = {
  addProposedSteps: (nodes: WorkflowNode[], edges: WorkflowEdge[]) => void;
  addStepAt: (draft: NewStepDraft, placement: StepPlacement) => void;
  addingAt: StepPlacement | null;
  applyHistory: (direction: 'redo' | 'undo') => void;
  askBefore: (key: string, summary: string, name: string) => void;
  change: (recipe: (copy: WorkingCopy) => WorkingCopy, shouldRemember?: boolean) => void;
  connect: (edge: WorkflowEdge) => 'circle' | 'exists' | 'full' | 'ok';
  copy: WorkingCopy;
  disconnect: (edge: WorkflowEdge) => void;
  editable: boolean;
  future: WorkingCopy[];
  isDrawerOpen: boolean;
  load: (workflow: Workflow, options?: { restored?: WorkingCopy }) => void;
  markSaved: (next: Partial<SavedCopy>, revision: string) => void;
  moveTo: (key: string, point: Point) => void;
  openDrawer: (placement: StepPlacement | null) => void;
  closeDrawer: () => void;
  outsideChange: OutsideChange | null;
  panel: BuilderPanel;
  past: WorkingCopy[];
  remember: () => void;
  removeSelected: (key: string) => void;
  revision: string | null;
  saveError: string | null;
  saveStatus: SaveStatus;
  saved: SavedCopy | null;
  select: (selection: BuilderSelection) => void;
  selection: BuilderSelection;
  setBaseFromServer: (workflow: Workflow) => void;
  setEditable: (editable: boolean) => void;
  setOutsideChange: (change: OutsideChange | null) => void;
  setSaveStatus: (status: SaveStatus, error?: string | null) => void;
  showPanel: (panel: BuilderPanel) => void;
  startNew: (name: string, restored?: WorkingCopy) => void;
  status: string;
  tidy: () => void;
  updateNode: (key: string, recipe: (node: WorkflowNode) => WorkflowNode) => void;
  version: number;
  workflowId: string | null;
};

const HISTORY_LIMIT = 50;

function makeEmptyCopy(name: string): WorkingCopy {
  return {
    description: '',
    edges: [],
    failureAlert: 'administrators',
    name,
    nodes: [],
    positions: {},
    runLimitSeconds: DEFAULT_RUN_LIMIT_SECONDS,
    trigger: { type: 'manual' },
  };
}

function toSavedCopy(copy: WorkingCopy): SavedCopy {
  return {
    description: copy.description,
    failureAlert: copy.failureAlert,
    graph: { edges: copy.edges, nodes: copy.nodes },
    name: copy.name,
    positions: copy.positions,
    runLimitSeconds: copy.runLimitSeconds,
    trigger: copy.trigger,
  };
}

function keepSelection(selection: BuilderSelection, copy: WorkingCopy): BuilderSelection {
  if (selection?.type === 'step' && !findStep(copy.nodes, selection.key)) {
    return null;
  }

  if (selection?.type === 'wire' && !selection.isImplied && !isExistingEdge(copy, selection.edge)) {
    return null;
  }

  return selection;
}

export const useWorkingCopy = create<WorkingCopyState>((set, get) => ({
  addProposedSteps: (nodes, edges) => {
    const { copy, past } = get();

    set({
      copy: tidyWorkingCopy({
        ...copy,
        edges: [...copy.edges, ...edges],
        nodes: [...copy.nodes, ...nodes],
      }),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
      selection: null,
    });
  },
  addStepAt: ({ fallbackKey, name, step }, placement) => {
    const { copy, past } = get();
    const key = makeNodeKey(copy, name, fallbackKey);
    const node = { ...step, key, name } as WorkflowNode;

    set({
      addingAt: null,
      copy: addStep(copy, node, placement),
      future: [],
      isDrawerOpen: false,
      past: [...past, copy].slice(-HISTORY_LIMIT),
      selection: { key, type: 'step' },
    });
  },
  addingAt: null,
  applyHistory: (direction) => {
    const { copy, future, past, selection } = get();
    const from = direction === 'undo' ? past : future;
    const target = from[from.length - 1];

    if (!target) {
      return;
    }

    set({
      copy: target,
      future: direction === 'undo' ? [...future, copy] : future.slice(0, -1),
      past: direction === 'undo' ? past.slice(0, -1) : [...past, copy],
      selection: keepSelection(selection, target),
    });
  },
  askBefore: (key, summary, name) => {
    const { copy, past } = get();
    const target = findStep(copy.nodes, key);
    const approvalKey = makeNodeKey(copy, name, 'approval');
    const approval: WorkflowNode & WorkflowApprovalStep = {
      action_class: target?.kind === 'action' ? target.effect : 'undeclared',
      key: approvalKey,
      kind: 'approval',
      name,
      summary,
      window_seconds: 24 * 60 * 60,
    };

    set({
      copy: addApprovalBefore(copy, approval, key),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
      selection: { key: approvalKey, type: 'step' },
    });
  },
  change: (recipe, shouldRemember = true) => {
    const { copy, past, selection } = get();
    const next = recipe(copy);

    set({
      copy: next,
      future: shouldRemember ? [] : get().future,
      past: shouldRemember ? [...past, copy].slice(-HISTORY_LIMIT) : past,
      selection: keepSelection(selection, next),
    });
  },
  closeDrawer: () => set({ addingAt: null, isDrawerOpen: false }),
  connect: (edge) => {
    const { copy, past } = get();

    if (copy.edges.length >= MAX_ARROWS) {
      return 'full';
    }

    if (!canConnectSteps(copy, edge)) {
      return isExistingEdge(copy, edge) ? 'exists' : 'circle';
    }

    set({
      copy: connectSteps(copy, edge),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
    });

    return 'ok';
  },
  copy: makeEmptyCopy(''),
  disconnect: (edge) => {
    const { copy, past } = get();

    set({
      copy: disconnectSteps(copy, edge),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
      selection: null,
    });
  },
  editable: false,
  future: [],
  isDrawerOpen: false,
  load: (workflow, options) => {
    const loaded = toWorkingCopy(workflow);

    set({
      addingAt: null,
      copy: options?.restored ?? loaded,
      future: [],
      isDrawerOpen: false,
      past: [],
      revision: workflow.revision,
      saveError: null,
      saveStatus: 'idle',
      saved: toSavedCopy(loaded),
      selection: null,
      status: workflow.status,
      version: workflow.version,
      workflowId: workflow.id,
    });
  },
  markSaved: (next, revision) => {
    const { saved } = get();

    if (saved) {
      set({ revision, saved: { ...saved, ...next } });
    }
  },
  moveTo: (key, point) => {
    set((state) => ({ copy: moveStep(state.copy, key, point) }));
  },
  openDrawer: (placement) => set({ addingAt: placement, isDrawerOpen: true }),
  outsideChange: null,
  panel: 'touches',
  past: [],
  remember: () => {
    const { copy, past } = get();

    if (past[past.length - 1] !== copy) {
      set({ future: [], past: [...past, copy].slice(-HISTORY_LIMIT) });
    }
  },
  removeSelected: (key) => {
    const { copy, past } = get();

    set({
      copy: removeStep(copy, key),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
      selection: null,
    });
  },
  revision: null,
  saveError: null,
  saveStatus: 'idle',
  saved: null,
  select: (selection) => set({ selection }),
  selection: null,
  setBaseFromServer: (workflow) => {
    set({
      revision: workflow.revision,
      saved: toSavedCopy(toWorkingCopy(workflow)),
      status: workflow.status,
    });
  },
  setEditable: (editable) => set({ editable }),
  setOutsideChange: (outsideChange) => set({ outsideChange }),
  setSaveStatus: (saveStatus, saveError = null) => set({ saveError, saveStatus }),
  showPanel: (panel) => set({ panel, selection: null }),
  startNew: (name, restored) => {
    set({
      addingAt: null,
      copy: restored ?? makeEmptyCopy(name),
      future: [],
      isDrawerOpen: false,
      panel: 'touches',
      past: [],
      revision: null,
      saveError: null,
      saveStatus: 'idle',
      saved: null,
      selection: { type: 'trigger' },
      status: 'draft',
      version: 1,
      workflowId: null,
    });
  },
  status: 'draft',
  tidy: () => {
    const { copy, past } = get();

    set({
      copy: tidyWorkingCopy(copy),
      future: [],
      past: [...past, copy].slice(-HISTORY_LIMIT),
    });
  },
  updateNode: (key, recipe) => {
    set((state) => ({ copy: updateStep(state.copy, key, recipe) }));
  },
  version: 1,
  workflowId: null,
}));
