'use client';

import { use, useCallback } from 'react';

import { SamlBrowserStep } from '@/components/auth/saml-browser-step';
import { signInToSamlApp } from '@/lib/api';

type PageProps = {
  params: Promise<{ appId: string; orgSlug: string; tenantSlug: string }>;
};

export default function SamlAppSignInPage({ params }: PageProps) {
  const { appId, orgSlug, tenantSlug } = use(params);
  const run = useCallback(
    () => signInToSamlApp({ orgSlug, tenantSlug }, appId),
    [appId, orgSlug, tenantSlug],
  );

  return <SamlBrowserStep context={{ orgSlug, tenantSlug }} needsSession run={run} />;
}
