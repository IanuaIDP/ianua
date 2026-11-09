'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useLocale, useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { useNotification } from '@/components/ui/notifications';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import {
  chooseOrganizationPlan,
  deriveErrorMessage,
  getApiErrorMessage,
  getOrganizationSubscription,
  getPlanChoices,
  startOrganizationCheckout,
  type BillingCycle,
  type BillingPlan,
} from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';

import { SettingsCard } from '../settings-card';

function formatDay(value: string, locale: string) {
  return new Date(value).toLocaleDateString(locale, { dateStyle: 'medium' });
}

export function SubscriptionSettingsSection() {
  const t = useTranslations('dashboard.settings.subscription');
  const tErrors = useTranslations('common.errors');
  const locale = useLocale();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { canManageBilling } = useOrgAccess();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const subscriptionQueryKey = ['organization-subscription', organizationSlug];
  const {
    data: subscription,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getOrganizationSubscription(organizationSlug ?? ''),
    queryKey: subscriptionQueryKey,
  });
  const { data: planChoices = [] } = useQuery({
    enabled: canManageBilling,
    queryFn: getPlanChoices,
    queryKey: ['plan-choices'],
  });
  const [selectedPlan, setSelectedPlan] = useState<BillingPlan | null>(null);
  const [selectedCycle, setSelectedCycle] = useState<BillingCycle | null>(null);
  const plan = selectedPlan ?? subscription?.plan ?? 'Free';
  const cycle = selectedCycle ?? subscription?.cycle ?? 'monthly';
  const hasChoice = plan !== subscription?.plan || cycle !== subscription?.cycle;
  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { isPending: isChoosingPlan, mutate: choosePlan } = useMutation({
    mutationFn: () => chooseOrganizationPlan(organizationSlug ?? '', plan, cycle),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('chooseFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setSelectedPlan(null);
      setSelectedCycle(null);
      showNotification({ message: t('chosen'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: subscriptionQueryKey });
    },
  });
  const { isPending: isStartingCheckout, mutate: startCheckout } = useMutation({
    mutationFn: () => startOrganizationCheckout(organizationSlug ?? ''),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('checkoutFailed')),
        type: 'error',
      });
    },
    onSuccess: (checkoutUrl) => window.location.assign(checkoutUrl),
  });

  const planOptions = planChoices.map((choice) => ({
    label: choice.displayName,
    value: choice.plan,
  }));
  const cycleOptions = [
    { label: t('cycles.monthly'), value: 'monthly' },
    { label: t('cycles.annual'), value: 'annual' },
  ];

  return (
    <SettingsCard title={t('title')} description={t('description')}>
      {errorMessage ? <p className="text-sm font-medium text-error">{errorMessage}</p> : null}

      {subscription ? (
        <div className="flex flex-col gap-4">
          <dl className="grid gap-4 sm:grid-cols-3">
            <div>
              <dt className="text-xs font-medium text-textGray">{t('plan')}</dt>
              <dd className="mt-1 text-sm font-semibold text-white">{subscription.plan}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-textGray">{t('cycle')}</dt>
              <dd className="mt-1 text-sm font-semibold text-white">
                {t(`cycles.${subscription.cycle}`)}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-textGray">{t('standing')}</dt>
              <dd className="mt-1 text-sm font-semibold text-white">
                {t(`states.${subscription.state}`)}
              </dd>
            </div>
          </dl>

          {subscription.trialEndsAt ? (
            <p className="text-xs font-medium text-textGray">
              {t('trialEnds', { date: formatDay(subscription.trialEndsAt, locale) })}
            </p>
          ) : null}
          {subscription.pastDueSince ? (
            <p className="rounded-lg border border-orange/50 bg-orange/10 px-3 py-2 text-xs font-medium text-orange">
              {t('pastDue', { date: formatDay(subscription.pastDueSince, locale) })}
            </p>
          ) : null}

          {canManageBilling ? (
            <div className="flex flex-col gap-4 border-t border-borderGray pt-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Select
                  label={t('choosePlan')}
                  containerClassName="mb-0"
                  options={planOptions}
                  value={plan}
                  onChange={(value) => setSelectedPlan(value as BillingPlan)}
                />
                <Select
                  label={t('chooseCycle')}
                  containerClassName="mb-0"
                  options={cycleOptions}
                  value={cycle}
                  onChange={(value) => setSelectedCycle(value as BillingCycle)}
                />
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  variant="focus"
                  isLoading={isChoosingPlan}
                  disabled={!hasChoice}
                  onClick={() => choosePlan()}
                  className="w-auto px-4 py-1.5 font-medium tracking-normal"
                >
                  {t('savePlan')}
                </Button>
                {!subscription.hasPaymentMethod ? (
                  <Button
                    type="button"
                    variant="outline"
                    isLoading={isStartingCheckout}
                    onClick={() => startCheckout()}
                    className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
                  >
                    {t('addPaymentMethod')}
                  </Button>
                ) : (
                  <p className="text-xs font-medium text-textGray">{t('paymentOnFile')}</p>
                )}
              </div>
            </div>
          ) : (
            <p className="text-xs font-medium text-textGray">{t('viewOnly')}</p>
          )}
        </div>
      ) : isLoading ? (
        <p className="text-xs font-medium text-textGray">{t('loading')}</p>
      ) : null}
    </SettingsCard>
  );
}
