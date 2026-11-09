import { getSandbox, getSandboxes } from '@/lib/api/services/sandboxes';
import type { Sandbox, SandboxVersion } from '@/types/sandbox';

export type RunnableSandboxVersion = {
  sandbox: Sandbox;
  version: SandboxVersion;
};

const SANDBOXES_PAGE = 100;
const VERSIONS_KEPT = 50;

/**
 * Every built version of an active sandbox, for a code step to name. The API
 * has no read of a version by its id, so each sandbox is read in turn.
 */
export async function getRunnableSandboxVersions(
  orgSlug: string,
  tenantSlug: string,
): Promise<RunnableSandboxVersion[]> {
  const { items } = await getSandboxes(orgSlug, tenantSlug, { limit: SANDBOXES_PAGE });
  const active = items.filter(
    (sandbox) => sandbox.status === 'active' && sandbox.latestVersion > 0,
  );
  const details = await Promise.all(
    active.map((sandbox) => getSandbox(orgSlug, tenantSlug, sandbox.id, { limit: VERSIONS_KEPT })),
  );

  return details.flatMap(({ sandbox, versions }) =>
    versions.items
      .filter((version) => version.build.status === 'ready')
      .map((version) => ({ sandbox, version })),
  );
}
