import { apiClient } from '@/lib/api/client';
import type {
  AccountSharing,
  WorkflowAccount,
  WorkflowAccountChange,
  WorkflowAccountList,
} from '@/types/workflows';

type AccountResponse = {
  created_at: string;
  id: string;
  integration: string;
  name: string;
  operations?: string[] | null;
  owner: string;
  sharing: string;
  status: string;
  updated_at: string;
};

type AccountsResponse = {
  items: AccountResponse[];
  limit: number;
  next_cursor?: string | null;
};

type ConnectAccountInput = {
  credential: string;
  integration: string;
  name: string;
  operations?: string[] | null;
  sharing: AccountSharing;
};

type BeginConnectionInput = {
  integration: string;
  name: string;
  operations?: string[] | null;
  place?: string;
  sharing: AccountSharing;
};

function getAccountsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows/accounts`;
}

function toAccount(response: AccountResponse): WorkflowAccount {
  return {
    createdAt: response.created_at,
    id: response.id,
    integration: response.integration,
    name: response.name,
    operations: response.operations ?? null,
    owner: response.owner,
    sharing: response.sharing,
    status: response.status,
    updatedAt: response.updated_at,
  };
}

/** One page of the tenant's integration accounts. No credential ever comes back. */
export async function getWorkflowAccounts(
  orgSlug: string,
  tenantSlug: string,
  { after, limit }: { after?: string; limit?: number } = {},
): Promise<WorkflowAccountList> {
  const { data } = await apiClient.get<AccountsResponse>(getAccountsEndpoint(orgSlug, tenantSlug), {
    params: { after, limit },
  });

  return { items: data.items.map(toAccount), nextCursor: data.next_cursor ?? null };
}

/** Connects an account with a key. The service is asked first, so a bad key saves nothing. */
export async function connectWorkflowAccount(
  orgSlug: string,
  tenantSlug: string,
  input: ConnectAccountInput,
) {
  const { data } = await apiClient.post<AccountResponse>(
    getAccountsEndpoint(orgSlug, tenantSlug),
    input,
  );

  return toAccount(data);
}

/** Begins signing in at the service; the browser is sent to the returned address. */
export async function beginWorkflowAccountConnection(
  orgSlug: string,
  tenantSlug: string,
  input: BeginConnectionInput,
) {
  const { data } = await apiClient.post<{ address: string; connection_id: string }>(
    `${getAccountsEndpoint(orgSlug, tenantSlug)}/connections`,
    input,
  );

  return { address: data.address, connectionId: data.connection_id };
}

/** Finishes a sign-in with the one-time code the service brought back. */
export async function finishWorkflowAccountConnection(
  orgSlug: string,
  tenantSlug: string,
  connectionId: string,
  code: string,
) {
  const { data } = await apiClient.post<AccountResponse>(
    `${getAccountsEndpoint(orgSlug, tenantSlug)}/connections/${encodeURIComponent(connectionId)}/finish`,
    { code },
  );

  return toAccount(data);
}

/** Makes one change to an account. */
export async function changeWorkflowAccount(
  orgSlug: string,
  tenantSlug: string,
  accountId: string,
  change: WorkflowAccountChange,
) {
  const { data } = await apiClient.patch<AccountResponse>(
    `${getAccountsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(accountId)}`,
    change,
  );

  return toAccount(data);
}
