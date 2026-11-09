import type { WorkingCopy } from '@/components/dashboard/workflows/builder/working-copy';

export type DraftStash = {
  baseRevision: string | null;
  copy: WorkingCopy;
};

function getStashKey(orgSlug: string, tenantSlug: string, workflowId: string | null) {
  return `ianua.workflow-draft.${orgSlug}.${tenantSlug}.${workflowId ?? 'new'}`;
}

/** A draft not fully saved yet, kept for this tab so a reload loses nothing. */
export function readDraftStash(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string | null,
): DraftStash | null {
  try {
    const raw = window.sessionStorage.getItem(getStashKey(orgSlug, tenantSlug, workflowId));

    return raw ? (JSON.parse(raw) as DraftStash) : null;
  } catch {
    return null;
  }
}

export function writeDraftStash(
  orgSlug: string,
  tenantSlug: string,
  workflowId: string | null,
  stash: DraftStash,
) {
  try {
    window.sessionStorage.setItem(
      getStashKey(orgSlug, tenantSlug, workflowId),
      JSON.stringify(stash),
    );
  } catch {
    return;
  }
}

export function clearDraftStash(orgSlug: string, tenantSlug: string, workflowId: string | null) {
  try {
    window.sessionStorage.removeItem(getStashKey(orgSlug, tenantSlug, workflowId));
  } catch {
    return;
  }
}
