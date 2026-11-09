import type { SelectOption } from '@/types/dashboard';
import type { CryptoMigration, CryptoMigrationAction } from '@/types/crypto';

export const SIGNING_ALGORITHM_OPTIONS: SelectOption[] = [
  { label: 'RS256', value: 'RS256' },
  { label: 'ES256', value: 'ES256' },
  { label: 'EdDSA', value: 'EdDSA' },
];

export const CRYPTO_MIGRATION_ACTIONS_BY_STATUS: Partial<
  Record<CryptoMigration['status'], CryptoMigrationAction[]>
> = {
  InProgress: ['Rollback', 'Promote'],
  Planned: ['Cancel', 'Start'],
  Validating: ['Rollback', 'Complete'],
};
