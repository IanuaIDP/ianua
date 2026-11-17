import { ANALYTICS_COOKIE_NAMES, ANALYTICS_COOKIE_PREFIXES } from '@/constants/analytics';

function isAnalyticsCookie(name: string): boolean {
  return (
    (ANALYTICS_COOKIE_NAMES as readonly string[]).includes(name) ||
    ANALYTICS_COOKIE_PREFIXES.some((prefix) => name.startsWith(prefix))
  );
}

function domainsToClear(): string[] {
  const parts = window.location.hostname.split('.');
  const parents = parts.slice(1).map((_, index) => `.${parts.slice(index + 1).join('.')}`);

  return ['', window.location.hostname, ...parents];
}

/** Deletes the cookies the analytics providers set, on this host and its parents. */
export function clearAnalyticsCookies() {
  const names = document.cookie
    .split(';')
    .map((entry) => entry.split('=')[0]?.trim() ?? '')
    .filter(isAnalyticsCookie);

  for (const name of names) {
    for (const domain of domainsToClear()) {
      const scope = domain ? `; domain=${domain}` : '';
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/${scope}`;
    }
  }
}
