'use client';

import { useTranslations } from 'next-intl';

import { TableCellText } from '@/components/ui/table-cell';
import type { UserAttribute, UserAttributeValue } from '@/types/user-attribute';
import {
  formatAttributeDateTime,
  formatAttributeDay,
  formatAttributeNumber,
} from '@/utils/attribute-format';

type AttributeValueCellProps = {
  attribute: UserAttribute;
  value: UserAttributeValue;
};

const chipClassName =
  'inline-flex h-5 shrink-0 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white';

/**
 * One stored value as a directory shows it.
 *
 * A control that paints rather than writes decides its own reading — a colour
 * is a swatch, a rating is stars, a list is chips. Everything else reads from
 * what the field holds, so an amount looks the same whether it was captured
 * by an amount box or a plain number box.
 */
export function AttributeValueCell({ attribute, value }: AttributeValueCellProps) {
  const t = useTranslations('dashboard.userFields');
  if (value === null || value === undefined || value === '') {
    return <TableCellText>—</TableCellText>;
  }

  if (attribute.control === 'colour_picker') {
    return (
      <span className="flex items-center gap-1.5">
        <span
          className="size-3.5 shrink-0 rounded-sm border border-borderGray"
          style={{ backgroundColor: String(value) }}
        />
        <TableCellText className="font-mono">{String(value)}</TableCellText>
      </span>
    );
  }

  if (attribute.control === 'star_rating') {
    const maximum = attribute.maximum ?? 5;

    return (
      <span
        className="flex items-center gap-0.5 text-orange"
        aria-label={t('valueCell.rating', { max: maximum, value: Number(value) })}
      >
        {Array.from({ length: maximum }, (_, index) => (
          <span
            key={index}
            className="material-symbols-rounded text-sm!"
            style={index < Number(value) ? { fontVariationSettings: "'FILL' 1" } : { opacity: 0.3 }}
          >
            star
          </span>
        ))}
      </span>
    );
  }

  if (Array.isArray(value)) {
    return (
      <span className="flex flex-wrap items-center gap-1">
        {value.slice(0, 3).map((entry) => (
          <span key={entry} className={chipClassName}>
            {entry}
          </span>
        ))}
        {value.length > 3 ? (
          <span className="text-[10px] font-medium text-textGray">+{value.length - 3}</span>
        ) : null}
      </span>
    );
  }

  if (typeof value === 'boolean') {
    return (
      <span
        className={`inline-flex h-5 shrink-0 items-center rounded-md px-1.5 text-[10px] font-medium leading-none ${
          value ? 'bg-primary/15 text-primary' : 'bg-white/15 text-white'
        }`}
      >
        {value ? t('valueCell.yes') : t('valueCell.no')}
      </span>
    );
  }

  if (typeof value === 'number') {
    return (
      <TableCellText className="tabular-nums">
        {formatAttributeNumber(attribute.kind, value)}
      </TableCellText>
    );
  }

  if (attribute.kind === 'date') {
    return <TableCellText className="tabular-nums">{formatAttributeDay(value)}</TableCellText>;
  }

  if (attribute.kind === 'date_time') {
    return <TableCellText className="tabular-nums">{formatAttributeDateTime(value)}</TableCellText>;
  }

  return <TableCellText>{value}</TableCellText>;
}
