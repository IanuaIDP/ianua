import { z } from 'zod';

import { microsFromAmount } from '@/utils/micros';

export const SANDBOX_LIMITS = {
  maxHosts: 20,
  maxMemoryMib: 2048,
  maxRunSeconds: 300,
  maxSteps: 50,
  maxTries: 3,
  minMemoryMib: 64,
  minRunSeconds: 1,
} as const;

export const CreateSandboxSchema = z.object({
  name: z.string().trim().min(1, 'validation.nameRequired'),
  runs: z.enum(['python', 'javascript', 'image']),
});

export type CreateSandboxFormInput = z.infer<typeof CreateSandboxSchema>;

const exactVersion = /^[^\s<>=~^*|]+$/;

const packageRow = z.object({
  name: z.string().trim().min(1, 'validation.packageNameRequired'),
  version: z
    .string()
    .trim()
    .min(1, 'validation.packageVersionRequired')
    .regex(exactVersion, 'validation.packageVersionExact'),
});

export const SandboxVersionSchema = z
  .object({
    accountId: z.string(),
    agentId: z.string(),
    allowedHosts: z.array(z.string()).max(SANDBOX_LIMITS.maxHosts, 'validation.hostsTooMany'),
    approvalClasses: z.array(z.string()),
    askPast: z.string(),
    code: z.string(),
    goal: z.string(),
    holdsAgent: z.boolean(),
    image: z.string(),
    kind: z.enum(['code', 'image']),
    maxSteps: z.union([z.number(), z.nan()]),
    memoryMib: z
      .number({ error: 'validation.memoryRange' })
      .int('validation.memoryRange')
      .min(SANDBOX_LIMITS.minMemoryMib, 'validation.memoryRange')
      .max(SANDBOX_LIMITS.maxMemoryMib, 'validation.memoryRange'),
    packages: z.array(packageRow),
    path: z.string(),
    providerId: z.string(),
    purpose: z.array(z.string()),
    ref: z.string(),
    repository: z.string(),
    runSeconds: z
      .number({ error: 'validation.runSecondsRange' })
      .int('validation.runSecondsRange')
      .min(SANDBOX_LIMITS.minRunSeconds, 'validation.runSecondsRange')
      .max(SANDBOX_LIMITS.maxRunSeconds, 'validation.runSecondsRange'),
    runtime: z.string(),
    source: z.enum(['write', 'import']),
    spendCap: z.string(),
    tools: z.array(z.string()),
    tries: z.union([z.number(), z.nan()]),
  })
  .superRefine((value, context) => {
    const require = (path: keyof typeof value, message: string) => {
      if (!String(value[path]).trim()) {
        context.addIssue({ code: 'custom', message, path: [path] });
      }
    };

    if (value.kind === 'image') {
      require('image', 'validation.imageRequired');
      return;
    }

    require('runtime', 'validation.runtimeRequired');

    if (value.source === 'write') {
      require('code', 'validation.codeRequired');
    } else {
      require('accountId', 'validation.accountRequired');
      require('repository', 'validation.repositoryRequired');
      require('path', 'validation.filePathRequired');
      require('ref', 'validation.refRequired');
    }

    if (value.holdsAgent) {
      refineHeldAgent(value, require, context);
    }
  });

function refineHeldAgent(
  value: {
    askPast: string;
    maxSteps: number;
    spendCap: string;
    tries: number;
  },
  require: (path: 'agentId' | 'goal' | 'providerId', message: string) => void,
  context: z.RefinementCtx,
) {
  require('agentId', 'validation.agentRequired');
  require('providerId', 'validation.providerRequired');
  require('goal', 'validation.goalRequired');

  if (!Number.isInteger(value.maxSteps) || value.maxSteps < 1 || value.maxSteps > 50) {
    context.addIssue({ code: 'custom', message: 'validation.maxStepsRange', path: ['maxSteps'] });
  }

  if (!Number.isInteger(value.tries) || value.tries < 1 || value.tries > 3) {
    context.addIssue({ code: 'custom', message: 'validation.triesRange', path: ['tries'] });
  }

  const cap = microsFromAmount(value.spendCap);

  if (cap === null || cap <= 0) {
    context.addIssue({
      code: 'custom',
      message: 'validation.spendCapRequired',
      path: ['spendCap'],
    });
  }

  if (!value.askPast.trim()) {
    return;
  }

  const askPast = microsFromAmount(value.askPast);

  if (askPast === null || cap === null || askPast >= cap) {
    context.addIssue({ code: 'custom', message: 'validation.askPastBelowCap', path: ['askPast'] });
  }
}

export type SandboxVersionFormInput = z.infer<typeof SandboxVersionSchema>;

export const WriteCodeSchema = z.object({
  inputs: z.array(z.string()),
  providerId: z.string().min(1, 'validation.providerRequired'),
  words: z.string().trim().min(1, 'validation.wordsRequired').max(500, 'validation.wordsTooLong'),
});

export type WriteCodeFormInput = z.infer<typeof WriteCodeSchema>;

export const PushVersionSchema = z.object({
  accountId: z.string().min(1, 'validation.accountRequired'),
  branch: z.string().trim().min(1, 'validation.branchRequired'),
  folder: z.string().trim().min(1, 'validation.folderRequired'),
  repository: z.string().trim().min(1, 'validation.repositoryRequired'),
});

export type PushVersionFormInput = z.infer<typeof PushVersionSchema>;

export const AllowRegistrySchema = z
  .object({
    host: z.string().trim().min(1, 'validation.hostRequired'),
    password: z.string(),
    username: z.string().trim(),
  })
  .superRefine((value, context) => {
    if (Boolean(value.username) !== Boolean(value.password)) {
      context.addIssue({
        code: 'custom',
        message: 'validation.loginBothOrNeither',
        path: [value.username ? 'password' : 'username'],
      });
    }
  });

export type AllowRegistryFormInput = z.infer<typeof AllowRegistrySchema>;
