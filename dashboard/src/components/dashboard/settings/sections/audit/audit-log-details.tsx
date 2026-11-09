import {
  flattenDetailValue,
  formatSectionTitle,
  toDisplayValue,
} from '@/lib/audit/audit-log-details';
import { isPlainObject } from '@/utils/object';

type AuditLogDetailsProps = {
  details: Record<string, unknown>;
};

export function AuditLogDetails({ details }: AuditLogDetailsProps) {
  const sections = Object.entries(details).filter(
    ([, value]) => value !== null && value !== undefined,
  );

  if (sections.length === 0) {
    return null;
  }

  return (
    <div className="pb-3">
      <div className="flex flex-col gap-3 rounded-lg border bg-surfaceChip border-borderGray px-4 py-3">
        {sections.map(([sectionKey, sectionValue]) => {
          const rows = isPlainObject(sectionValue)
            ? flattenDetailValue(sectionValue)
            : [{ key: sectionKey, value: toDisplayValue(sectionValue) }];

          if (rows.length === 0) {
            return null;
          }

          return (
            <div key={sectionKey}>
              <p className="mb-1.5 text-xs font-semibold text-white">
                {formatSectionTitle(sectionKey)}
              </p>
              <div className="rounded-lg border border-borderGray px-4 py-2.5 font-mono text-xs leading-relaxed">
                {rows.map((row) => (
                  <p key={row.key} className="truncate">
                    <span className="text-badgeViolet">{row.key}:</span>{' '}
                    <span className="text-primary">{row.value}</span>
                  </p>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
