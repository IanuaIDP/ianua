export type IndicatorState =
  'hidden' | 'locked' | 'authenticating' | 'authenticationSuccessful' | 'opening' | 'accessGranted';

export type PricingPlan = {
  badge?: string;
  buttonHref: string;
  buttonLabel: string;
  buttonTone?: 'default' | 'focus';
  features: string[];
  footnote?: string;
  heading?: string;
  hidePricePeriod?: boolean;
  highlighted?: boolean;
  isCustom?: boolean;
  listTitle: string;
  name: string;
  price: {
    annual: string;
    monthly: string;
  };
  requirementsDescription?: string;
  subtitle: string;
};
