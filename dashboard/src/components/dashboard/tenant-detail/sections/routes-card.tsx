'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { HttpRoutesCard } from '@/components/dashboard/tenant-detail/sections/routes/http-routes-card';
import { StreamRoutesCard } from '@/components/dashboard/tenant-detail/sections/routes/stream-routes-card';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { ROUTE_KIND_PARAM, STREAM_ROUTE_KIND } from '@/constants/stream-route';

type RouteKind = 'http' | 'stream';

/**
 * Both kinds of route the proxy serves, under one heading.
 *
 * They are one feature seen at two layers, not two features: the same
 * permission governs them, the same audit trail records them, and an operator
 * looking for "where does this traffic go" should not have to know in advance
 * which layer answered.
 */
export function RoutesCard() {
  const t = useTranslations('dashboard.routes');
  const kindOptions: { label: string; value: RouteKind }[] = [
    { label: t('kinds.http'), value: 'http' },
    { label: t('kinds.stream'), value: 'stream' },
  ];
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const activeKind: RouteKind =
    searchParams.get(ROUTE_KIND_PARAM) === STREAM_ROUTE_KIND ? 'stream' : 'http';

  function selectKind(kind: RouteKind) {
    const params = new URLSearchParams(searchParams.toString());

    if (kind === 'stream') {
      params.set(ROUTE_KIND_PARAM, STREAM_ROUTE_KIND);
    } else {
      params.delete(ROUTE_KIND_PARAM);
    }

    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }

  const kindControl = (
    <SegmentedControl
      ariaLabel={t('protocolAria')}
      options={kindOptions}
      value={activeKind}
      onChange={selectKind}
    />
  );

  if (activeKind === 'stream') {
    return <StreamRoutesCard titleControl={kindControl} />;
  }

  return <HttpRoutesCard titleControl={kindControl} />;
}
