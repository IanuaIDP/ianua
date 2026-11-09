import type { ReactNode } from 'react';

type PanelFieldProps = {
  aside?: ReactNode;
  children: ReactNode;
  hint?: ReactNode;
  label: ReactNode;
};

/** One labelled field of the step panel. */
export function PanelField({ aside, children, hint, label }: PanelFieldProps) {
  return (
    <div className="mt-5">
      <div className="mb-2 flex items-center justify-between gap-2 text-xs font-semibold text-white">
        <span>{label}</span>
        {aside ? <span className="font-normal text-textGray">{aside}</span> : null}
      </div>
      {children}
      {hint ? <p className="mt-1.5 text-xs text-textGray">{hint}</p> : null}
    </div>
  );
}

type PanelNoteProps = {
  children: ReactNode;
  icon: string;
  tone?: 'danger' | 'neutral' | 'warning';
};

const NOTE_TONES = {
  danger: 'text-error',
  neutral: 'text-textGray',
  warning: 'text-orange',
};

/** A quiet line about the step, with an icon showing how much it matters. */
export function PanelNote({ children, icon, tone = 'neutral' }: PanelNoteProps) {
  return (
    <div className="mt-4 flex gap-2 text-xs text-textGray">
      <span
        className={`material-symbols-rounded text-base! ${NOTE_TONES[tone]}`}
        aria-hidden="true"
      >
        {icon}
      </span>
      <span>{children}</span>
    </div>
  );
}

type PanelAlertProps = {
  action?: ReactNode;
  children?: ReactNode;
  icon: string;
  title: ReactNode;
  tone?: 'danger' | 'warning';
};

/** Something the person must act on before the step can run. */
export function PanelAlert({ action, children, icon, title, tone = 'warning' }: PanelAlertProps) {
  return (
    <div
      className={`mt-4 flex gap-2.5 rounded-lg p-3 ${
        tone === 'danger' ? 'bg-error/10' : 'bg-orange/10'
      }`}
    >
      <span
        className={`material-symbols-rounded ${tone === 'danger' ? 'text-error' : 'text-orange'}`}
        aria-hidden="true"
      >
        {icon}
      </span>
      <div className="min-w-0 flex-1 text-xs text-white">
        <p className="font-semibold">{title}</p>
        {children ? <div className="mt-1 text-textGray">{children}</div> : null}
        {action ? <div className="mt-2.5 flex flex-wrap gap-2">{action}</div> : null}
      </div>
    </div>
  );
}
