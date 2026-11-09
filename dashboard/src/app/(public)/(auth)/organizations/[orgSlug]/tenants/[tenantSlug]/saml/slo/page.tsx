'use client';

import { Suspense, use, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';

import { SamlBrowserStep } from '@/components/auth/saml-browser-step';
import { answerSamlAppLogout } from '@/lib/api';
import { readSamlMessage } from '@/lib/auth/saml-message';

type PageProps = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
};

function SamlLogoutContent({ orgSlug, tenantSlug }: { orgSlug: string; tenantSlug: string }) {
  const searchParams = useSearchParams();
  const run = useCallback(async () => {
    const message = readSamlMessage(new URLSearchParams(searchParams.toString()));

    if (!message) {
      throw new Error('no SAML message');
    }

    return answerSamlAppLogout({ orgSlug, tenantSlug }, message);
  }, [orgSlug, searchParams, tenantSlug]);

  return <SamlBrowserStep context={{ orgSlug, tenantSlug }} needsSession={false} run={run} />;
}

export default function SamlLogoutPage({ params }: PageProps) {
  const { orgSlug, tenantSlug } = use(params);

  return (
    <Suspense>
      <SamlLogoutContent orgSlug={orgSlug} tenantSlug={tenantSlug} />
    </Suspense>
  );
}
