'use client';

import { useCallback, use } from 'react';
import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';

import { SamlBrowserStep } from '@/components/auth/saml-browser-step';
import { answerSamlSignIn } from '@/lib/api';

type PageProps = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
};

function SamlSignInContent({ orgSlug, tenantSlug }: { orgSlug: string; tenantSlug: string }) {
  const request = useSearchParams().get('request') ?? '';
  const context = { orgSlug, tenantSlug };
  const run = useCallback(
    () => answerSamlSignIn({ orgSlug, tenantSlug }, request),
    [orgSlug, request, tenantSlug],
  );

  return <SamlBrowserStep context={context} needsSession run={run} />;
}

export default function SamlSignInPage({ params }: PageProps) {
  const { orgSlug, tenantSlug } = use(params);

  return (
    <Suspense>
      <SamlSignInContent orgSlug={orgSlug} tenantSlug={tenantSlug} />
    </Suspense>
  );
}
