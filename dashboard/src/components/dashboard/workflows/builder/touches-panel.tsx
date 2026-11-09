'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { PanelAlert } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import {
  getLeakingSteps,
  getOutsideIntegrations,
  getTouchedPlaces,
} from '@/components/dashboard/workflows/builder/what-it-touches';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { cn } from '@/utils/cn';

const LEVEL_DOTS: Record<string, string> = {
  confidential: 'bg-orange',
  restricted: 'bg-error',
};

/** What the workflow can reach, read from its steps as they stand. */
export function TouchesPanel() {
  const t = useTranslations('dashboard.workflowBuilder.touches');
  const tVerb = useLooseTranslations('dashboard.workflowBuilder.touches.verbs');
  const { text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const places = useMemo(() => getTouchedPlaces(copy), [copy]);
  const leaks = useMemo(() => getLeakingSteps(copy), [copy]);
  const outside = useMemo(() => getOutsideIntegrations(copy), [copy]);
  const verbs = [...new Set(places.map((place) => place.verb))];

  return (
    <div className="flex-1 overflow-auto p-4">
      <p className="text-base font-bold text-white">{t('title')}</p>
      <p className="mt-2 text-xs text-textGray">{t('help')}</p>

      {verbs.length === 0 ? <p className="mt-4 text-sm text-textGray">{t('nothingYet')}</p> : null}

      {verbs.map((verb) => (
        <div key={verb} className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-textGray">
            {tVerb(verb)}
          </p>
          {places
            .filter((place) => place.verb === verb)
            .map((place) => (
              <p
                key={place.integration}
                className="mt-1 flex items-center gap-2 rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white"
              >
                {text.getIntegrationTitle(place.integration)}
                <span
                  aria-label={place.level}
                  className={cn('size-2 rounded-full', LEVEL_DOTS[place.level] ?? 'bg-menuHover')}
                />
              </p>
            ))}
        </div>
      ))}

      <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-wide text-textGray">{t('actsAs')}</p>
        <p className="mt-1 rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white">
          {t('person')}
        </p>
      </div>

      <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-wide text-textGray">
          {t('outside')}
        </p>
        <p className="mt-1 rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white">
          {outside.length > 0
            ? outside.map((key) => text.getIntegrationTitle(key)).join(', ')
            : t('nothingOutside')}
        </p>
      </div>

      {leaks.length > 0 ? (
        <PanelAlert icon="shield" title={t('leakTitle')} tone="danger">
          {leaks.map((step) => (
            <p key={step.key}>
              {t('leak', {
                service: text.getIntegrationTitle(step.integration),
                step: step.name,
              })}
            </p>
          ))}
        </PanelAlert>
      ) : null}
    </div>
  );
}
