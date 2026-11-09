import { WorkflowApproval } from '@/components/auth/workflow-approval';

type PageProps = {
  params: Promise<{ orgSlug: string; runId: string; step: string; tenantSlug: string }>;
  searchParams: Promise<{ decision?: string }>;
};

export default async function WorkflowApprovalPage({ params, searchParams }: PageProps) {
  const { orgSlug, runId, step, tenantSlug } = await params;
  const { decision } = await searchParams;

  return (
    <WorkflowApproval
      orgSlug={orgSlug}
      preselectedDecision={decision}
      runId={runId}
      step={decodeURIComponent(step)}
      tenantSlug={tenantSlug}
    />
  );
}
