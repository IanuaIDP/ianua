import { useTranslations } from 'next-intl';

import {
  DISCOVERY_KINDS,
  SIGN_IN_DELIVERY_KINDS,
  SIGNED_OUT_BROWSER_KINDS,
  STICKY_SESSION_KINDS,
} from '@/constants/service';
import type { SelectOption } from '@/types/dashboard';
import type {
  DiscoveryKind,
  SignInAddresses,
  SignInDeliveryKind,
  SignedOutBrowsers,
} from '@/types/gateway-service';
import type { StickySession, StickySessionKind } from '@/types/route';

/** The choices of the service forms, worded in the current language. */
export function useServiceOptions() {
  const t = useTranslations('dashboard.services');

  const discoveryKindOptions: (SelectOption & { value: DiscoveryKind })[] = DISCOVERY_KINDS.map(
    (kind) => ({ label: t(`discovery.kinds.${kind}`), value: kind }),
  );
  const stickySessionOptions: (SelectOption & { value: 'None' | StickySessionKind })[] =
    STICKY_SESSION_KINDS.map((kind) => ({ label: t(`sticky.kinds.${kind}`), value: kind }));
  const signInDeliveryOptions: (SelectOption & { value: SignInDeliveryKind })[] =
    SIGN_IN_DELIVERY_KINDS.map((kind) => ({
      label: t(`appSignIn.delivery.${kind}`),
      value: kind,
    }));
  const signedOutBrowserOptions: (SelectOption & { value: SignedOutBrowsers })[] =
    SIGNED_OUT_BROWSER_KINDS.map((kind) => ({
      label: t(`appSignIn.signedOut.${kind}`),
      value: kind,
    }));

  function signInDeliveryHint(kind: SignInDeliveryKind) {
    return kind === 'tokens'
      ? t('appSignIn.deliveryHints.tokens', {
          example: '{ "audience": "<this service’s audience>" }',
        })
      : t(`appSignIn.deliveryHints.${kind}`);
  }

  function stickySessionLabel(stickySession: StickySession | null) {
    if (!stickySession) {
      return t('sticky.kinds.None');
    }

    return stickySession.kind === 'Cookie' || stickySession.kind === 'Header'
      ? t(`sticky.withValue.${stickySession.kind}`, { value: stickySession.value })
      : t(`sticky.kinds.${stickySession.kind}`);
  }

  return {
    discoveryKindOptions,
    signInAddressLabel: (key: keyof SignInAddresses) => t(`appSignIn.addresses.${key}`),
    signInDeliveryHint,
    signInDeliveryOptions,
    signedOutBrowserOptions,
    stickySessionLabel,
    stickySessionOptions,
  };
}
