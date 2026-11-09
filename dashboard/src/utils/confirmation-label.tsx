import { useTranslations } from 'next-intl';

type ConfirmationLabelProps = {
  /** A full sentence that contains `value`; the default one is used when omitted. */
  label?: string;
  value: string;
};

/** "If you're sure, please type X to confirm:" with the typed value picked out. */
export function ConfirmationLabel({ label, value }: ConfirmationLabelProps) {
  const t = useTranslations('dashboard.confirm');
  const valueIndex = label?.indexOf(value) ?? -1;

  if (label && valueIndex === -1) {
    return label;
  }

  if (!label) {
    return t.rich('typeToConfirm', {
      text: value,
      value: (chunks) => <span className="text-white">{chunks}</span>,
    });
  }

  return (
    <>
      {label.slice(0, valueIndex)}
      <span className="text-white">{value}</span>
      {label.slice(valueIndex + value.length)}
    </>
  );
}
