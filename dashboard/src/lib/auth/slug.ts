export function getDisplayNameFromSlug(slug: string) {
  return slug
    .split(/[-_]+/)
    .filter(Boolean)
    .map((word) => `${word[0]?.toUpperCase() ?? ''}${word.slice(1)}`)
    .join(' ');
}
