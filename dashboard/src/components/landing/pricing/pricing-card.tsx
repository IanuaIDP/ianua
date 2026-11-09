import { PricingPlan } from '@/types/landing';
import { cn } from '@/utils/cn';
import Link from 'next/link';
import { useTranslations } from 'next-intl';

type PricingCardProps = {
  billingPeriod: 'monthly' | 'annual';
  className?: string;
  plan: PricingPlan;
};

export function PricingCard({ billingPeriod, className, plan }: PricingCardProps) {
  const t = useTranslations('landing.pricing');
  const buttonClassName =
    plan.highlighted || plan.buttonTone === 'focus'
      ? 'bg-focus text-white hover:bg-hoverBgPurple'
      : 'border border-borderGray bg-hoverBg text-white hover:bg-cardBg';
  const priceLabel = billingPeriod === 'monthly' ? t('perMonth') : t('perYear');

  return (
    <article
      className={cn(
        'flex flex-col overflow-hidden rounded-[10px] border text-left self-center',
        plan.highlighted ? 'border-primary bg-brand-gradient' : 'border-borderGray',
        className,
      )}
    >
      {plan.badge && (
        <div className="flex items-center justify-center bg-brand-gradient px-6 py-2.5 text-center font-['Space_Grotesk','Manrope',sans-serif] text-xs font-bold uppercase text-appBg">
          {plan.badge}
        </div>
      )}

      <div
        className={cn(
          'flex flex-1 flex-col',
          plan.highlighted &&
            'mx-1 mb-1 overflow-hidden rounded-md bg-[linear-gradient(180deg,#10120B_0%,#090A05_100%)]',
        )}
      >
        {plan.isCustom ? (
          <>
            <div className="px-4 py-8 text-center">
              <p className="text-sm font-bold uppercase text-focus">{plan.name}</p>
              <p className="mt-4 font-['Space_Grotesk','Manrope',sans-serif] text-[32px] font-bold leading-none text-white">
                {plan.heading ?? plan.name}
              </p>
              <p className="mx-auto mt-3 max-w-60 text-sm text-textGray">{plan.subtitle}</p>
            </div>

            <div className="flex flex-col border-y border-borderGray py-6">
              <div className="px-4">
                <p className="font-['Space_Grotesk','Manrope',sans-serif] text-sm font-medium text-white">
                  {plan.listTitle}
                </p>
                <p className="mt-3 text-xs leading-5 text-textGray">
                  {plan.requirementsDescription}
                </p>
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="px-4 py-8 text-center">
              <p className="text-sm font-bold uppercase text-primary">{plan.name}</p>
              <p className="mt-4 font-['Space_Grotesk','Manrope',sans-serif] text-[32px] font-bold leading-none text-white">
                {plan.price[billingPeriod]}
              </p>
              {!plan.hidePricePeriod && <p className="mt-1 text-sm text-textGray">{priceLabel}</p>}
              <p className="mt-1 text-sm text-white">{plan.subtitle}</p>
            </div>

            <div className="flex flex-1 flex-col border-y border-borderGray py-6">
              <div className="px-4">
                <p className="font-['Space_Grotesk','Manrope',sans-serif] text-sm font-medium text-white">
                  {plan.listTitle}
                </p>

                <ul className="mt-3 flex flex-1 flex-col text-xs leading-5 text-textGray">
                  {plan.features.map((feature) => (
                    <li
                      key={feature}
                      className="grid grid-cols-[1rem_minmax(0,1fr)] items-start gap-1.5"
                    >
                      <span
                        className="material-symbols-rounded mt-1 flex size-4 items-center justify-center overflow-hidden text-[13px]! text-primary"
                        aria-hidden="true"
                      >
                        check
                      </span>
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </>
        )}

        <div className="flex flex-col items-center gap-2 py-6">
          <Link
            href={plan.buttonHref}
            className={cn(
              'inline-flex h-11 w-fit items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition-colors duration-200',
              plan.isCustom ? 'border border-focus text-focus hover:bg-focus/10' : buttonClassName,
            )}
          >
            {plan.buttonLabel}
            {!plan.isCustom && (
              <span className="material-symbols-rounded" aria-hidden="true">
                arrow_forward
              </span>
            )}
          </Link>

          {plan.footnote && <p className="text-xs text-textGray">{plan.footnote}</p>}
        </div>
      </div>
    </article>
  );
}

export type { PricingPlan };
