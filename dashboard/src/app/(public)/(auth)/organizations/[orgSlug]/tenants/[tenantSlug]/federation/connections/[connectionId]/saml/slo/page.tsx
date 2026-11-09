'use client';

import { Suspense, use, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';

import { SamlBrowserStep } from '@/components/auth/saml-browser-step';
import { answerConnectionSamlLogout } from '@/lib/api';
import { readSamlMessage } from '@/lib/auth/saml-message';

type PageProps = {
  params: Promise<{ connectionId: string; orgSlug: string; tenantSlug: string }>;
};

type ContentProps = { connectionId: string; orgSlug: string; tenantSlug: string };

function ConnectionLogoutContent({ connectionId, orgSlug, tenantSlug }: ContentProps) {
  const searchParams = useSearchParams();
  const run = useCallback(async () => {
    const message = readSamlMessage(new URLSearchParams(searchParams.toString()));

    if (!message) {
      throw new Error('no SAML message');
    }

    return answerConnectionSamlLogout({ orgSlug, tenantSlug }, connectionId, message);
  }, [connectionId, orgSlug, searchParams, tenantSlug]);

  return <SamlBrowserStep context={{ orgSlug, tenantSlug }} needsSession={false} run={run} />;
}

export default function ConnectionLogoutPage({ params }: PageProps) {
  const { connectionId, orgSlug, tenantSlug } = use(params);

  return (
    <Suspense>
      <ConnectionLogoutContent
        connectionId={connectionId}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
      />
    </Suspense>
  );
}
