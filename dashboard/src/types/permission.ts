export type PermissionValue = Record<string, string>;

export type Permission = {
  label: string;
  value: PermissionValue;
};

export type PermissionGroup = {
  label: string;
  permissions: Permission[];
};

export type TenantPermissionResource =
  | 'Agents'
  | 'ApiKeys'
  | 'AuditLog'
  | 'AuthConfig'
  | 'Branding'
  | 'Classification'
  | 'Compliance'
  | 'Consumers'
  | 'Crypto'
  | 'Domains'
  | 'Federation'
  | 'Messaging'
  | 'Metrics'
  | 'Mtls'
  | 'Pipeline'
  | 'PolicySet'
  | 'Roles'
  | 'Routing'
  | 'Scim'
  | 'Signals'
  | 'TenantSettings'
  | 'Users'
  | 'Webhooks'
  | 'Workflows';

export type TenantPermissionAction =
  | 'Activate'
  | 'Approve'
  | 'Assign'
  | 'Configure'
  | 'ConnectAccounts'
  | 'Consume'
  | 'Create'
  | 'Deactivate'
  | 'Delegate'
  | 'Delete'
  | 'Export'
  | 'Manage'
  | 'Publish'
  | 'Revoke'
  | 'Run'
  | 'Update'
  | 'View';
