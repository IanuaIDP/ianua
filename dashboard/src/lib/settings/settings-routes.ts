export function getSettingsTabHref(label: string) {
  return `/settings?tab=${encodeURIComponent(label)}`;
}
