import { OAuthConsent } from '@/components/auth/oauth-consent';

type PageProps = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function asSingleValues(query: Record<string, string | string[] | undefined>) {
  return Object.fromEntries(
    Object.entries(query).flatMap(([name, value]) =>
      typeof value === 'string' ? [[name, value]] : [],
    ),
  );
}

export default async function OAuthAuthorizePage({ params, searchParams }: PageProps) {
  const { orgSlug, tenantSlug } = await params;

  return (
    <OAuthConsent context={{ orgSlug, tenantSlug }} request={asSingleValues(await searchParams)} />
  );
}
