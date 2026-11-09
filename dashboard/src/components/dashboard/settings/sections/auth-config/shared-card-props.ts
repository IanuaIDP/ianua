import type { Control, FieldErrors, UseFormRegister } from 'react-hook-form';

import type { SharedAuthConfigFields } from '@/schemas/auth-config-schemas';

/**
 * What every shared sign-in card needs from the form it sits in.
 *
 * Typed against [`SharedAuthConfigFields`] rather than either whole form,
 * because the cards only ever touch the fields both forms state identically.
 * A workspace form and an organization form each contain that shape, so each
 * one hands its control over at the call site.
 */
export type AuthConfigCardProps = {
  control: Control<SharedAuthConfigFields>;
  errors: FieldErrors<SharedAuthConfigFields>;
  isBusy: boolean;
  register: UseFormRegister<SharedAuthConfigFields>;
};
