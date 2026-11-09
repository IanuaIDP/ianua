'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantUserActionsMenu } from '@/components/dashboard/tenant-detail/sections/tenant-users/tenant-user-actions-menu';
import { AttributeValueCell } from '@/components/dashboard/tenant-detail/sections/user-attributes/attribute-value-cell';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { TableCellStack, TableCellText } from '@/components/ui/table-cell';
import type { SelectOption } from '@/types/dashboard';
import type { UserAttribute } from '@/types/user-attribute';
import type {
  TenantUser,
  TenantUserAction,
  TenantUserSortDirection,
  TenantUserSortField,
} from '@/types/tenant-user';
import { isNumericKind } from '@/utils/attribute-format';
import { getBadgeColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';

type TenantUsersTableProps = {
  /** The tenant's own fields marked to show in the list, in declared order. */
  attributeColumns?: UserAttribute[];
  canAssignRoles?: boolean;
  canDeactivateUser?: boolean;
  canDeleteUser?: boolean;
  canUpdateUser?: boolean;
  currentUserEmail?: string;
  /** Whether the tenant keeps any fields at all, listed or not. */
  hasFields?: boolean;
  isLoading?: boolean;
  onEditFieldsClick: (user: TenantUser) => void;
  onResetPasswordClick: (user: TenantUser) => void;
  onRoleChange: (user: TenantUser, roleIds: string[]) => void;
  onSortChange: (field: TenantUserSortField) => void;
  onUserAction: (user: TenantUser, action: TenantUserAction) => Promise<void> | void;
  roleOptions: SelectOption[];
  sortDirection?: TenantUserSortDirection;
  sortField?: TenantUserSortField;
  updatingRoleUserId?: string | null;
  users: TenantUser[];
};

/**
 * The built-in columns, each stated once with the two widths it can take.
 *
 * On its own the table shares the width it has, in percentages. Once custom
 * columns join, percentages stop working — a table of `table-fixed` scales
 * every share down to fit rather than growing — so each column claims a fixed
 * width instead and the table scrolls. The class is written out because a
 * width assembled at runtime is a class no stylesheet contains.
 */
type BaseColumn = {
  label: string;
  pixelClassName: string;
  pixelWidth: number;
  shareClassName: string;
  sortField?: TenantUserSortField;
};

const baseColumns: BaseColumn[] = [
  {
    label: 'User',
    pixelClassName: 'w-[260px]',
    pixelWidth: 260,
    shareClassName: 'w-[26%]',
    sortField: 'display_name',
  },
  { label: 'Role', pixelClassName: 'w-[190px]', pixelWidth: 190, shareClassName: 'w-[16%]' },
  { label: 'Verified', pixelClassName: 'w-[120px]', pixelWidth: 120, shareClassName: 'w-[13%]' },
  {
    label: 'Status',
    pixelClassName: 'w-[140px]',
    pixelWidth: 140,
    shareClassName: 'w-[14%]',
    sortField: 'status',
  },
  {
    label: 'Last login',
    pixelClassName: 'w-[150px]',
    pixelWidth: 150,
    shareClassName: 'w-[14%]',
    sortField: 'last_login_at',
  },
  {
    label: 'Joined',
    pixelClassName: 'w-[140px]',
    pixelWidth: 140,
    shareClassName: 'w-[14%]',
    sortField: 'created_at',
  },
];

const attributeColumnClassName = 'w-[170px]';
const attributeColumnWidth = 170;
const actionsColumnWidth = 48;

/**
 * Keeps whoever the row is about in view however far right you scroll. The
 * edge shows where scrolled columns pass beneath it.
 */
const stickyUserColumnClassName = 'sticky left-0 z-20 shadow-[1px_0_0_0_theme(colors.borderGray)]';

const baseColumnsWidth = baseColumns.reduce((total, column) => total + column.pixelWidth, 0);

/**
 * The built-in columns plus one per listed custom field.
 *
 * A custom column carries no `sortField`, because ordering by one is not a
 * column sort — it goes through `sort=attr:...` and is offered by the filter
 * bar above the table instead.
 */
function buildColumns(attributeColumns: UserAttribute[], translate: (label: string) => string) {
  const isWide = attributeColumns.length > 0;

  return [
    ...baseColumns.map(({ label, pixelClassName, shareClassName, sortField }) => ({
      className: isWide
        ? cn(pixelClassName, label === 'User' && stickyUserColumnClassName)
        : shareClassName,
      label: translate(label),
      sortField,
    })),
    ...attributeColumns.map((attribute) => ({
      className: attributeColumnClassName,
      label: attribute.displayName,
      // An amount is read against the column beside it, so a numeric heading
      // sits over its digits rather than away from them.
      labelClassName: isNumericKind(attribute.kind) ? 'block text-right' : undefined,
    })),
  ] as DashboardTableColumn<TenantUserSortField>[];
}

/** Nothing to impose while the table still fits the width it is given. */
function tableMinWidth(attributeColumns: UserAttribute[]) {
  if (attributeColumns.length === 0) {
    return undefined;
  }

  return baseColumnsWidth + actionsColumnWidth + attributeColumns.length * attributeColumnWidth;
}

export function TenantUsersTable({
  attributeColumns = [],
  canAssignRoles = true,
  canDeactivateUser = true,
  canDeleteUser = true,
  canUpdateUser = true,
  currentUserEmail,
  hasFields = false,
  isLoading = false,
  onEditFieldsClick,
  onResetPasswordClick,
  onRoleChange,
  onSortChange,
  onUserAction,
  roleOptions,
  sortDirection,
  sortField,
  updatingRoleUserId,
  users,
}: TenantUsersTableProps) {
  const t = useTranslations('dashboard.tenantUsers');
  const tColumns = useLooseTranslations('dashboard.tenantUsers.columns');

  return (
    <DashboardTableShell
      className="mt-4"
      columns={buildColumns(attributeColumns, (label) => tColumns(label))}
      hasActionsColumn
      isEmpty={users.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidth={tableMinWidth(attributeColumns)}
      minWidthClassName="min-w-230"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {users.map((user) => {
        const isSelf =
          Boolean(currentUserEmail) &&
          Boolean(user.email) &&
          user.email.toLowerCase() === currentUserEmail?.toLowerCase();

        return (
          <tr key={user.id} className="group h-11 transition hover:bg-hoverBg">
            <td
              className={cn(
                'px-4 py-2',
                attributeColumns.length > 0 &&
                  `${stickyUserColumnClassName} bg-cardBg group-hover:bg-hoverBg`,
              )}
            >
              <div className="flex min-w-0 items-center gap-3">
                <span
                  className={cn(
                    'flex size-6 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                    getBadgeColorClass(user.email),
                  )}
                >
                  {user.avatarInitial}
                </span>
                <TableCellStack
                  primary={isSelf ? t('me', { name: user.displayName }) : user.displayName}
                  primaryClassName="font-semibold text-white"
                  secondary={user.email}
                  secondaryClassName="text-[10px] font-medium text-textGray"
                />
              </div>
            </td>
            <td className="px-4 py-2">
              {user.invitedRole ? (
                <TableCellText className="text-textGray">
                  {t('onAccepting', { role: user.invitedRole.name })}
                </TableCellText>
              ) : canAssignRoles ? (
                <MultiSelect
                  containerClassName="mb-0"
                  className="h-8 bg-cardBg"
                  options={roleOptions}
                  value={user.roles.map((role) => role.id)}
                  disabled={updatingRoleUserId === user.id}
                  onChange={(roleIds) => onRoleChange(user, roleIds)}
                />
              ) : (
                <TableCellText>
                  {user.roles.length > 0 ? user.roles.map((role) => role.name).join(', ') : '—'}
                </TableCellText>
              )}
            </td>
            <td className="px-4 py-2">
              <span
                className={
                  user.emailVerified
                    ? 'inline-flex h-5 items-center rounded-md bg-primary/15 px-1.5 text-[10px] font-medium leading-none text-primary'
                    : 'inline-flex h-5 items-center rounded-md bg-error/15 px-1.5 text-[10px] font-medium leading-none text-error'
                }
              >
                {user.emailVerified ? t('verified') : t('notVerified')}
              </span>
            </td>
            <td className="px-4 py-2">
              <DashboardStatusBadge status={user.status} />
            </td>
            <td className="px-4 py-2">
              <TableCellText>{user.lastLogin}</TableCellText>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{user.created}</TableCellText>
            </td>
            {attributeColumns.map((attribute) => (
              <td
                key={`${attribute.namespace}.${attribute.key}`}
                className={cn('px-4 py-2', isNumericKind(attribute.kind) && 'text-right')}
              >
                <AttributeValueCell
                  attribute={attribute}
                  value={user.attributes[`${attribute.namespace}.${attribute.key}`] ?? null}
                />
              </td>
            ))}
            <DashboardTableActionsCell>
              <TenantUserActionsMenu
                canDeactivate={canDeactivateUser}
                canDelete={canDeleteUser}
                canUpdate={canUpdateUser}
                hasFields={hasFields}
                isSelf={isSelf}
                user={user}
                onActionConfirm={onUserAction}
                onEditFieldsClick={onEditFieldsClick}
                onResetPasswordClick={onResetPasswordClick}
              />
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
