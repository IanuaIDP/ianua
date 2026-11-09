'use client';

import { useTranslations } from 'next-intl';

import { UserFieldIconButton } from '@/components/dashboard/tenant-detail/sections/user-attributes/user-field-icon-button';
import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { Switch } from '@/components/ui/Switch';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { UserAttribute } from '@/types/user-attribute';

type UserFieldRowProps = {
  attribute: UserAttribute;
  canDelete: boolean;
  canUpdate: boolean;
  isBusy: boolean;
  onArchiveChange: (attribute: UserAttribute, archived: boolean) => void;
  onDeleteClick: (attribute: UserAttribute) => void;
  onEditClick: (attribute: UserAttribute) => void;
  onListedChange: (attribute: UserAttribute, listed: boolean) => void;
};

/**
 * One field in the Manage fields popover. An active field can be shown in the
 * user list, edited and archived; an archived one can be restored or deleted.
 */
export function UserFieldRow({
  attribute,
  canDelete,
  canUpdate,
  isBusy,
  onArchiveChange,
  onDeleteClick,
  onEditClick,
  onListedChange,
}: UserFieldRowProps) {
  const t = useTranslations('dashboard.userFields');
  const tKinds = useLooseTranslations('dashboard.userFields.kinds');

  return (
    <li className="flex min-h-9.5 items-center gap-2 rounded-lg border border-borderGray bg-surfaceRaised px-3 py-1.5">
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <span className="truncate text-sm font-medium text-white">{attribute.displayName}</span>
        <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white">
          {tKinds.has(attribute.kind) ? tKinds(attribute.kind) : attribute.kind}
        </span>
        {attribute.sensitive ? (
          <FloatingTooltip content={t('row.sensitive')}>
            <span
              className="material-symbols-rounded text-sm! text-orange"
              aria-label={t('row.sensitive')}
            >
              lock
            </span>
          </FloatingTooltip>
        ) : null}
      </div>

      {attribute.archived ? (
        <div className="flex shrink-0 items-center gap-1">
          {canUpdate ? (
            <UserFieldIconButton
              disabled={isBusy}
              icon="unarchive"
              label={t('row.restore')}
              onClick={() => onArchiveChange(attribute, false)}
            />
          ) : null}
          {canDelete ? (
            <UserFieldIconButton
              disabled={isBusy}
              icon="delete"
              label={t('row.delete')}
              tone="danger"
              onClick={() => onDeleteClick(attribute)}
            />
          ) : null}
        </div>
      ) : (
        <div className="flex shrink-0 items-center gap-2">
          <FloatingTooltip content={attribute.listed ? t('row.hide') : t('row.show')}>
            <Switch
              aria-label={
                attribute.listed
                  ? t('row.hideAria', { name: attribute.displayName })
                  : t('row.showAria', { name: attribute.displayName })
              }
              checked={attribute.listed}
              disabled={!canUpdate || isBusy}
              onCheckedChange={(listed) => onListedChange(attribute, listed)}
            />
          </FloatingTooltip>
          {canUpdate ? (
            <div className="flex items-center gap-1">
              <UserFieldIconButton
                disabled={isBusy}
                icon="edit"
                label={t('row.edit')}
                onClick={() => onEditClick(attribute)}
              />
              <UserFieldIconButton
                disabled={isBusy}
                icon="archive"
                label={t('row.archive')}
                onClick={() => onArchiveChange(attribute, true)}
              />
            </div>
          ) : null}
        </div>
      )}
    </li>
  );
}
