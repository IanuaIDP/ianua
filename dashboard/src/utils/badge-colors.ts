export const BADGE_BACKGROUND_COLORS = [
  'bg-badgeViolet',
  'bg-badgeFuchsia',
  'bg-badgeBlue',
  'bg-badgeCyan',
  'bg-badgeGreen',
  'bg-badgeLime',
  'bg-badgeYellow',
  'bg-badgeOrange',
  'bg-badgeRed',
  'bg-badgePink',
] as const;

export const BADGE_SOFT_COLOR_CLASSES = [
  'bg-badgeViolet/15 text-badgeViolet',
  'bg-badgeFuchsia/15 text-badgeFuchsia',
  'bg-badgeBlue/15 text-badgeBlue',
  'bg-badgeCyan/15 text-badgeCyan',
  'bg-badgeGreen/15 text-badgeGreen',
  'bg-badgeLime/15 text-badgeLime',
  'bg-badgeYellow/15 text-badgeYellow',
  'bg-badgeOrange/15 text-badgeOrange',
  'bg-badgeRed/15 text-badgeRed',
  'bg-badgePink/15 text-badgePink',
] as const;

function hashSeed(seed: string | number) {
  const value = String(seed);
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }

  return hash;
}

export function getBadgeColorClass(seed: string | number) {
  return BADGE_BACKGROUND_COLORS[hashSeed(seed) % BADGE_BACKGROUND_COLORS.length];
}

export function getBadgeSoftColorClass(seed: string | number) {
  return BADGE_SOFT_COLOR_CLASSES[hashSeed(seed) % BADGE_SOFT_COLOR_CLASSES.length];
}
