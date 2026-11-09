import { useTranslations } from 'next-intl';

import { TeamMemberStatus } from '@/types/team';
import type { OrganizationStatus } from '@/types/organization';
import type { ApiKeyStatus } from '@/types/api-key';
import type { ApprovalStatus } from '@/types/approval';
import type { CloudAccountStatus } from '@/types/cloud-account';
import type { ConnectionStatus } from '@/types/connection';
import type { CryptoKeyStatus, CryptoMigrationStatus } from '@/types/crypto';
import type { CredentialStatus } from '@/types/credential';
import type { DataClassLevel } from '@/types/classification';
import type { DelegationStatus } from '@/types/delegation';
import type { DeviceStatus } from '@/types/device';
import type { DomainTlsStatus, DomainVerificationStatus } from '@/types/domain';
import type { FlowStatus } from '@/types/flow';
import type { ModelProviderStatus } from '@/types/model-provider';
import type { PipelineStatus, StageStatus } from '@/types/pipeline';
import type { RouteStatus } from '@/types/route';
import type { RunStatus } from '@/types/run';
import type { DeliveryStatus, StreamStatus } from '@/types/stream';
import type { TenantAgentStanding, TenantAgentStatus } from '@/types/tenant-agent';
import type { ToolStatus } from '@/types/tool';
import type { TenantStatus } from '@/types/tenant';
import type { TenantApiKeyStatus } from '@/types/tenant-api-key';
import type { TenantUserStatus } from '@/types/tenant-user';
import { cn } from '@/utils/cn';
import { formatStatusLabel } from '@/utils/format-status-label';

type CombinedStatus =
  | ApiKeyStatus
  | ApprovalStatus
  | CloudAccountStatus
  | ConnectionStatus
  | CryptoKeyStatus
  | CryptoMigrationStatus
  | CredentialStatus
  | DataClassLevel
  | DelegationStatus
  | DeviceStatus
  | DomainTlsStatus
  | DomainVerificationStatus
  | FlowStatus
  | ModelProviderStatus
  | DeliveryStatus
  | PipelineStatus
  | StageStatus
  | RouteStatus
  | RunStatus
  | StreamStatus
  | TenantAgentStanding
  | TenantAgentStatus
  | TenantStatus
  | TenantApiKeyStatus
  | TeamMemberStatus
  | TenantUserStatus
  | OrganizationStatus
  | ToolStatus;

const statusStyles: Record<CombinedStatus, string> = {
  Draft: 'bg-white/15 text-white',
  Provisioning: 'bg-orange/15 text-orange',
  Active: 'bg-primary/15 text-primary',
  Suspended: 'bg-error/15 text-error',
  MustReattest: 'bg-orange/15 text-orange',
  Archived: 'bg-white/15 text-white',
  Closed: 'bg-white/15 text-white',
  OverBudget: 'bg-error/15 text-error',
  Closing: 'bg-orange/15 text-orange',
  Locked: 'bg-error/15 text-error',
  Paused: 'bg-orange/15 text-orange',
  Invited: 'bg-orange/15 text-orange',
  PendingVerification: 'bg-pendingVerification/15 text-pendingVerification',
  Revoked: 'bg-error/15 text-error',
  InvitationExpired: 'bg-invitationExpired/15 text-invitationExpired',
  Deactivated: 'bg-white/15 text-white',
  Trusted: 'bg-primary/15 text-primary',
  Public: 'bg-white/15 text-white',
  Internal: 'bg-focus/15 text-focus',
  Confidential: 'bg-orange/15 text-orange',
  Restricted: 'bg-error/15 text-error',
  Verified: 'bg-primary/15 text-primary',
  Pending: 'bg-orange/15 text-orange',
  Failed: 'bg-error/15 text-error',
  Enabled: 'bg-primary/15 text-primary',
  Disabled: 'bg-error/15 text-error',
  NotRequired: 'bg-white/15 text-white',
  Expired: 'bg-error/15 text-error',
  Rotated: 'bg-orange/15 text-orange',
  Planned: 'bg-focus/15 text-focus',
  InProgress: 'bg-primary/15 text-primary',
  Validating: 'bg-orange/15 text-orange',
  RolledBack: 'bg-white/15 text-white',
  Cancelled: 'bg-white/15 text-white',
  Running: 'bg-primary/15 text-primary',
  Completed: 'bg-badgeGreen/15 text-badgeGreen',
  Canceled: 'bg-white/15 text-white',
  Halted: 'bg-focus/15 text-focus',
  AwaitingApproval: 'bg-orange/15 text-orange',
  Approved: 'bg-badgeGreen/15 text-badgeGreen',
  Denied: 'bg-error/15 text-error',
  Success: 'bg-primary/15 text-primary',
  Timeout: 'bg-orange/15 text-orange',
  Unreachable: 'bg-pendingVerification/15 text-pendingVerification',
  Queued: 'bg-focus/15 text-focus',
};

type DashboardStatusBadgeProps = {
  status: CombinedStatus;
};

export function DashboardStatusBadge({ status }: DashboardStatusBadgeProps) {
  const t = useTranslations('dashboard.status');

  return (
    <span
      className={cn(
        'inline-flex h-5 shrink-0 items-center gap-1.25 whitespace-nowrap rounded-md px-1.5 text-[10px] font-medium leading-none',
        statusStyles[status],
      )}
    >
      {t.has(status) ? t(status) : formatStatusLabel(status)}
    </span>
  );
}
