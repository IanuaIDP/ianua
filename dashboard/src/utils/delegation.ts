import type { Delegation } from '@/types/delegation';

export function getDelegationPurpose(delegation: Delegation) {
  return delegation.name ? delegation.intent?.statement : undefined;
}

export function getCapabilityBadges(delegation: Delegation) {
  // Tools first, matching the order they are offered in when granting.
  const toolBadges = delegation.granted.tools;
  const httpBadges = delegation.granted.http;
  const messagingBadges = delegation.granted.messaging.map(
    (capability) => `${capability.topic} · ${capability.rights}`,
  );

  return [...toolBadges, ...httpBadges, ...messagingBadges];
}
