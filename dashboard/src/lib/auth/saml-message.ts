import type { SamlMessage } from '@/lib/api';

/** Reads the SAML message from the query a logout page was sent with. */
export function readSamlMessage(searchParams: URLSearchParams): SamlMessage | null {
  const binding = searchParams.get('binding');

  if (binding === 'redirect') {
    return { binding, query: searchParams.get('query') ?? '' };
  }

  if (binding === 'post') {
    return {
      binding,
      message: searchParams.get('message') ?? '',
      relayState: searchParams.get('relay_state'),
    };
  }

  return null;
}
