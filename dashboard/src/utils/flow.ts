import type { CSSProperties } from 'react';

import type { Flow, FlowNode, FlowNodeStatus } from '@/types/flow';

const SETTLED_NODE_STATUSES = new Set(['Completed', 'Failed']);

export type FlowStageStatus = 'Completed' | 'Failed' | 'Pending' | 'Running';

export function getFlowNodes(flow: Flow) {
  return flow.stages.flat();
}

export function getFlowNodeCounts(flow: Flow) {
  const nodes = getFlowNodes(flow);
  const settled = nodes.filter((node) => SETTLED_NODE_STATUSES.has(node.status)).length;

  return { settled, total: nodes.length };
}

export function getFlowStageDisplay(flow: Flow) {
  const totalStages = flow.stages.length;

  if (flow.status === 'Completed') {
    return { current: totalStages + 1, total: totalStages };
  }

  const displayedStage = Math.min(flow.currentStage + 1, Math.max(totalStages, 1));

  return { current: displayedStage, total: totalStages };
}

export function getFlowStageProgress(flow: Flow) {
  const { current, total } = getFlowStageDisplay(flow);

  if (total === 0) {
    return 0;
  }

  return Math.min((current / total) * 100, 100);
}

export function getFlowAgentCount(flow: Flow) {
  return new Set(getFlowNodes(flow).map((node) => node.agentId)).size;
}

export function getFlowStageStatus(stageNodes: FlowNode[]): FlowStageStatus {
  if (stageNodes.some((node) => node.status === 'Failed')) {
    return 'Failed';
  }

  if (stageNodes.some((node) => node.status === 'Dispatched')) {
    return 'Running';
  }

  if (stageNodes.length > 0 && stageNodes.every((node) => node.status === 'Completed')) {
    return 'Completed';
  }

  return 'Pending';
}

const FLOW_NODE_STATUS_META: Record<FlowNodeStatus, { className: string; label: string }> = {
  Completed: { className: 'bg-badgeGreen/15 text-badgeGreen', label: 'Completed' },
  Dispatched: { className: 'bg-primary/15 text-primary', label: 'Running' },
  Failed: { className: 'bg-error/15 text-error', label: 'Failed' },
  Pending: { className: 'bg-orange/15 text-orange', label: 'Pending' },
};

export function getFlowNodeStatusMeta(status: FlowNodeStatus) {
  return FLOW_NODE_STATUS_META[status];
}

const CONNECTOR_COLOR_BY_STAGE_STATUS: Record<FlowStageStatus, string> = {
  Completed: '#B1F15E',
  Failed: '#FF5D7A',
  Pending: '#2A2A28',
  Running: '#B1F15E',
};

const CONNECTOR_DASH_MASK_IMAGE =
  'repeating-linear-gradient(to bottom, #fff 0, #fff 4px, transparent 4px, transparent 8px)';

export function getFlowConnectorLineStyle(
  fromStatus: FlowStageStatus,
  toStatus: FlowStageStatus,
): CSSProperties {
  const backgroundImage = `linear-gradient(to bottom, ${CONNECTOR_COLOR_BY_STAGE_STATUS[fromStatus]} 0%, ${CONNECTOR_COLOR_BY_STAGE_STATUS[toStatus]} 100%)`;

  if (fromStatus === 'Completed') {
    return { backgroundImage };
  }

  return {
    WebkitMaskImage: CONNECTOR_DASH_MASK_IMAGE,
    backgroundImage,
    maskImage: CONNECTOR_DASH_MASK_IMAGE,
  };
}
