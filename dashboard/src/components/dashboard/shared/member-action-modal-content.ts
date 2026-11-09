import type { LooseTranslator } from '@/hooks/i18n/use-loose-translations';
import type { DashboardActionModalContent } from '@/types/dashboard';

export type MemberLifecycleAction =
  'Lock' | 'Delete Forever' | 'Restore Access' | 'Revoke Invitation';

/** Which wording to use: the messages are written out for each, as the cases differ. */
export type MemberKind = 'teamMember' | 'user';

/** `t` is the translator of `dashboard.memberActions`. */
export function createMemberActionModalContent(
  t: LooseTranslator,
  kind: MemberKind,
): Record<MemberLifecycleAction, DashboardActionModalContent> {
  return {
    Lock: {
      title: t(`${kind}.lock.title`),
      description: t(`${kind}.lock.description`),
      primaryActionLabel: t(`${kind}.lock.primary`),
    },
    'Delete Forever': {
      title: t(`${kind}.deleteForever.title`),
      description: t(`${kind}.deleteForever.description`),
      primaryActionLabel: t(`${kind}.deleteForever.primary`),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
    },
    'Restore Access': {
      title: t(`${kind}.restoreAccess.title`),
      description: t(`${kind}.restoreAccess.description`),
      primaryActionLabel: t(`${kind}.restoreAccess.primary`),
    },
    'Revoke Invitation': {
      title: t('revokeInvitation.title'),
      description: t('revokeInvitation.description'),
      primaryActionLabel: t('revokeInvitation.primary'),
    },
  };
}
