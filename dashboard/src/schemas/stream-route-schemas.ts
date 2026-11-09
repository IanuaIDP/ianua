import { z } from 'zod';

import {
  MAX_STREAM_IDLE_SECS,
  MAX_STREAM_LISTEN_PORT,
  MIN_STREAM_IDLE_SECS,
  MIN_STREAM_LISTEN_PORT,
} from '@/constants/stream-route';

function isNonNegativeInteger(value: string) {
  return /^\d+$/.test(value.trim());
}

const StreamBackendFormSchema = z.object({
  host: z.string().min(1, 'validation.backendHostRequired'),
  port: z.string().refine(isNonNegativeInteger, 'validation.portInvalid'),
  weight: z.string().refine(isNonNegativeInteger, 'validation.weightWhole'),
});

export const StreamRouteFormSchema = z
  .object({
    backends: z.array(StreamBackendFormSchema).min(1, 'validation.backendRequired'),
    connectSecs: z.string().refine(isNonNegativeInteger, 'validation.connectTimeoutInvalid'),
    idleSecs: z.string().refine(isNonNegativeInteger, 'validation.idleTimeoutInvalid'),
    listenPort: z.string().refine(isNonNegativeInteger, 'validation.portInvalid'),
    name: z.string().min(1, 'validation.nameRequired'),
    access: z.record(z.string(), z.unknown()).nullable().optional(),
    policy: z.enum(['public', 'mutual_tls', 'tunnel']),
    protocol: z.enum(['tcp', 'tls_terminate', 'tls_passthrough', 'udp']),
    sniNames: z.array(z.string()),
    sniRestricted: z.boolean(),
  })
  .superRefine((values, ctx) => {
    const port = Number(values.listenPort);
    if (port < MIN_STREAM_LISTEN_PORT || port > MAX_STREAM_LISTEN_PORT) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `validation.listenPortRange?min=${MIN_STREAM_LISTEN_PORT}&max=${MAX_STREAM_LISTEN_PORT}`,
        path: ['listenPort'],
      });
    }

    const idle = Number(values.idleSecs);
    if (idle < MIN_STREAM_IDLE_SECS || idle > MAX_STREAM_IDLE_SECS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `validation.idleTimeoutRange?min=${MIN_STREAM_IDLE_SECS}&max=${MAX_STREAM_IDLE_SECS}`,
        path: ['idleSecs'],
      });
    }

    // The rule the whole protocol choice exists to protect. A port that reads
    // as authenticated while admitting anyone is the worst kind of wrong,
    // because nothing reports it — so it is refused here as well as by the API.
    if (values.policy === 'mutual_tls' && values.protocol !== 'tls_terminate') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.mutualTlsProtocol',
        path: ['policy'],
      });
    }

    // A restriction that matches nothing is worse than no restriction: the
    // port looks narrowed and answers everything.
    if (
      values.sniRestricted &&
      values.protocol !== 'tls_terminate' &&
      values.protocol !== 'tls_passthrough'
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.sniProtocol',
        path: ['sniNames'],
      });
    }

    if (values.sniRestricted && values.sniNames.filter((name) => name.trim()).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'validation.sniRequired',
        path: ['sniNames'],
      });
    }

    values.backends.forEach((backend, index) => {
      const backendPort = Number(backend.port);
      if (backendPort < 1 || backendPort > MAX_STREAM_LISTEN_PORT) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'validation.backendPortRange',
          path: ['backends', index, 'port'],
        });
      }
      if (Number(backend.weight) < 1) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'validation.backendWeightMin',
          path: ['backends', index, 'weight'],
        });
      }
    });
  });

export type StreamRouteFormInput = z.infer<typeof StreamRouteFormSchema>;
