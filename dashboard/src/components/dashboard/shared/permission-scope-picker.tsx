'use client';

import { useTranslations } from 'next-intl';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { getApiErrorMessage } from '@/lib/api';
import { formatGroupLabel, formatPermissionLabel } from '@/lib/roles/permission-format';
import type { Permission, PermissionGroup } from '@/types/permission';
import { cn } from '@/utils/cn';

type PermissionScopePickerProps = {
  disabled?: boolean;
  error?: string;
  groups: PermissionGroup[];
  hint?: string;
  isLocked?: (permission: Permission) => boolean;
  isLoading?: boolean;
  isSelected: (permission: Permission) => boolean;
  label?: string;
  loadError?: unknown;
  onToggle: (permission: Permission) => void;
  onToggleAll: (permissions: Permission[]) => void;
};

export function PermissionScopePicker({
  disabled = false,
  error,
  groups,
  hint,
  isLocked,
  isLoading = false,
  isSelected,
  label,
  loadError,
  onToggle,
  onToggleAll,
}: PermissionScopePickerProps) {
  const t = useTranslations('dashboard.permissionPicker');
  const errorMessage = useFieldError(error);
  const allPermissions = groups.flatMap((group) => group.permissions);
  const selectedCount = allPermissions.filter(isSelected).length;
  const isAllSelected = allPermissions.length > 0 && selectedCount === allPermissions.length;

  function handleToggleAll() {
    onToggleAll(isAllSelected ? [] : allPermissions);
  }

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{label ?? t('label')}</span>
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-textGray">
            {isAllSelected
              ? t('allSelected', { count: selectedCount })
              : t('selected', { count: selectedCount })}
          </span>
          <button
            type="button"
            disabled={disabled || allPermissions.length === 0}
            onClick={handleToggleAll}
            className="text-xs font-semibold text-focus transition hover:text-focus/80 disabled:pointer-events-none disabled:opacity-60"
          >
            {isAllSelected ? t('deselectAll') : t('selectAll')}
          </button>
        </div>
      </div>
      {hint ? <p className="mb-2 text-xs text-textGray">{hint}</p> : null}

      {isLoading ? (
        <p className="text-xs text-textGray">{t('loading')}</p>
      ) : loadError ? (
        <p className="text-xs text-error">{getApiErrorMessage(loadError, t('loadFailed'))}</p>
      ) : (
        <div className="max-h-64 overflow-y-auto rounded-lg border border-borderGray">
          {groups.map((group, index) => {
            const groupSelectedCount = group.permissions.filter(isSelected).length;

            return (
              <div
                key={group.label}
                className={cn('px-3 py-2.5', index > 0 && 'border-t border-borderGray')}
              >
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-xs font-semibold text-white">
                    {formatGroupLabel(group.label)}
                  </span>
                  {groupSelectedCount > 0 ? (
                    <span className="text-xs font-semibold text-focus">{groupSelectedCount}</span>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {group.permissions.map((permission) => {
                    const selected = isSelected(permission);
                    const locked = selected && (isLocked?.(permission) ?? false);

                    return (
                      <button
                        key={permission.label}
                        type="button"
                        disabled={disabled || locked}
                        title={locked ? t('required') : undefined}
                        onClick={() => onToggle(permission)}
                        className={cn(
                          'rounded-full border px-2.5 py-1 text-xs font-medium transition disabled:pointer-events-none disabled:opacity-60',
                          selected
                            ? 'border-transparent bg-primary/15 text-primary'
                            : 'border-borderGray bg-surfaceRaised text-textGray hover:border-white/20 hover:text-white',
                        )}
                      >
                        {formatPermissionLabel(permission)}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {errorMessage ? <p className="mt-2 text-xs text-error">{errorMessage}</p> : null}
    </div>
  );
}
