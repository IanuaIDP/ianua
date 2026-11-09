import { z } from 'zod';

const assuranceLevel = z.enum(['Aal1', 'Aal2', 'Aal3']);
const riskLevel = z.enum(['Low', 'Medium', 'High', 'Critical']);

const authMethod = z.enum(['Password', 'MagicLink', 'Passkey', 'Saml', 'Oidc']);

// Org sign-in implements only these two, and the server refuses the rest.
const orgAuthMethod = z.enum(['Password', 'Passkey']);

const ASSURANCE_ORDER: Record<z.infer<typeof assuranceLevel>, number> = {
  Aal1: 1,
  Aal2: 2,
  Aal3: 3,
};

// Mirrors the server's own floors so a value it would refuse never leaves the
// browser. The server checks them again; this is for the error message, not
// for the guarantee.
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MIN_SESSION_SECS = 300;
const MAX_SESSION_SECS = 2_592_000;
const MIN_IDLE_SECS = 60;
const MIN_LOGIN_ATTEMPTS = 2;
const MAX_LOGIN_ATTEMPTS = 100;
const MIN_LOCKOUT_SECS = 30;
const MAX_LOCKOUT_SECS = 86_400;

/**
 * The rules a workspace and an organization state identically.
 *
 * Everything except which methods are on offer, and the two fields only a
 * workspace has. Shared so a change to the password floor or the lockout
 * ceiling cannot land on one screen and miss the other.
 */
const sharedAuthConfigFields = {
  breachedPasswords: z.enum(['Off', 'Warn', 'Block']).optional(),
  challengeThreshold: z.number().int().optional(),
  secondFactors: z.array(z.enum(['Totp', 'EmailCode', 'SmsCode'])).optional(),
  idleTimeoutSecs: z.number().int().min(MIN_IDLE_SECS, 'validation.atLeast60Seconds'),
  ipAllowlist: z.array(z.string()),
  lockoutDurationSecs: z
    .number()
    .int()
    .min(MIN_LOCKOUT_SECS, 'validation.atLeast30Seconds')
    .max(MAX_LOCKOUT_SECS, 'validation.atMost24Hours'),
  maxLoginAttempts: z
    .number()
    .int()
    .min(MIN_LOGIN_ATTEMPTS, 'validation.oneAttemptLocks')
    .max(MAX_LOGIN_ATTEMPTS, 'validation.atMost100'),
  mfaPolicy: z.enum(['Disabled', 'Optional', 'Required']),
  passwordPolicy: z.object({
    minLength: z
      .number()
      .int()
      .min(MIN_PASSWORD_LENGTH, 'validation.passwordMinLength')
      .max(MAX_PASSWORD_LENGTH, 'validation.passwordMaxLength'),
    require: z.object({
      digit: z.boolean(),
      lowercase: z.boolean(),
      special: z.boolean(),
      uppercase: z.boolean(),
    }),
  }),
  sessionLifetimeSecs: z
    .number()
    .int()
    .min(MIN_SESSION_SECS, 'validation.atLeast5Minutes')
    .max(MAX_SESSION_SECS, 'validation.atMost30Days'),
  stepUp: z.object({
    baselineAal: assuranceLevel,
    denyRiskThreshold: riskLevel,
    mfaRiskThreshold: riskLevel,
    requireMfaNewCountry: z.boolean(),
    requireMfaNewDevice: z.boolean(),
    sensitiveAal: assuranceLevel,
  }),
};

/**
 * The fields the shared setting cards read and write.
 *
 * Both form types contain this shape, which is what lets one set of cards
 * serve both screens.
 */
export type SharedAuthConfigFields = z.infer<z.ZodObject<typeof sharedAuthConfigFields>>;

// The two cross-field rules, as predicates rather than a schema wrapper: a
// wrapper generic enough to accept both schemas loses the field types on the
// way through, and then neither rule can read the fields it exists to compare.
const IDLE_OUTLASTS_SESSION = 'validation.idleOutlastsSession';
const SENSITIVE_IS_WEAKER = 'validation.sensitiveIsWeaker';

function idleFitsInsideSession(config: SharedAuthConfigFields) {
  return config.idleTimeoutSecs <= config.sessionLifetimeSecs;
}

function sensitiveIsNotWeakerThanBaseline(config: SharedAuthConfigFields) {
  return ASSURANCE_ORDER[config.stepUp.sensitiveAal] >= ASSURANCE_ORDER[config.stepUp.baselineAal];
}

export const AuthConfigSchema = z
  .object({
    ...sharedAuthConfigFields,
    enabledMethods: z.array(authMethod).min(1, 'validation.pickSignInMethod'),
    impersonationConsent: z.enum(['AdminDecides', 'HolderApproves']).optional(),
    jwtIssuer: z.string().optional(),
    selfRegistration: z.boolean(),
  })
  .refine(idleFitsInsideSession, { message: IDLE_OUTLASTS_SESSION, path: ['idleTimeoutSecs'] })
  .refine(sensitiveIsNotWeakerThanBaseline, {
    message: SENSITIVE_IS_WEAKER,
    path: ['stepUp', 'sensitiveAal'],
  });

export const OrgAuthConfigSchema = z
  .object({
    ...sharedAuthConfigFields,
    enabledMethods: z.array(orgAuthMethod).min(1, 'validation.pickSignInMethod'),
    sso: z.enum(['Optional', 'Enforced']).optional(),
  })
  .refine(idleFitsInsideSession, { message: IDLE_OUTLASTS_SESSION, path: ['idleTimeoutSecs'] })
  .refine(sensitiveIsNotWeakerThanBaseline, {
    message: SENSITIVE_IS_WEAKER,
    path: ['stepUp', 'sensitiveAal'],
  });

export type AuthConfigInput = z.infer<typeof AuthConfigSchema>;
export type OrgAuthConfigInput = z.infer<typeof OrgAuthConfigSchema>;
