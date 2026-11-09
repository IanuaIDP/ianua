import { apiClient } from '@/lib/api/client';
import type { TenantAuthContext } from '@/lib/api/services/auth';

/** A signed SAML message for the browser to post to the peer. */
export type SamlFormPost = {
  destination: string;
  fields: Record<string, string>;
};

/** A SAML message as the browser brought it, by binding. */
export type SamlMessage =
  | { binding: 'redirect'; query: string }
  | { binding: 'post'; message: string; relayState: string | null };

type SamlFormPostResponse = {
  destination: string;
  message: string;
  parameter: string;
  relay_state?: string | null;
};

type SamlMessageRequest =
  | { binding: 'post'; message: string; relay_state: string | null }
  | { binding: 'redirect'; query: string };

export type OAuthFormPost = {
  action: string;
  fields: Record<string, string>;
};

export type AuthorizeOutcome =
  | { kind: 'issued' | 'refused'; formPost: OAuthFormPost | null; redirectTo: string | null }
  | { kind: 'consent'; scopes: string[] }
  | { kind: 'sign_in' };

type AuthorizeResponse = {
  form_post?: { action: string; fields: Record<string, string> } | null;
  outcome: 'consent' | 'issued' | 'refused' | 'sign_in';
  redirect_to?: string | null;
  scopes?: string[];
};

export type EndSessionOutcome = {
  frontChannelLogoutUris: string[];
  outcome: 'confirm' | 'not_signed_in' | 'signed_out';
  redirectTo: string | null;
};

type EndSessionResponse = {
  front_channel_logout_uris: string[];
  outcome: EndSessionOutcome['outcome'];
  redirect_to?: string | null;
};

function getTenantEndpoint({ orgSlug, tenantSlug }: TenantAuthContext) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

function toSamlFormPost(response: SamlFormPostResponse): SamlFormPost {
  return {
    destination: response.destination,
    fields: {
      [response.parameter]: response.message,
      ...(response.relay_state ? { RelayState: response.relay_state } : {}),
    },
  };
}

function toSamlMessageRequest(message: SamlMessage): SamlMessageRequest {
  return message.binding === 'redirect'
    ? message
    : { binding: 'post', message: message.message, relay_state: message.relayState };
}

/** Answers the sign-in request an app sent, held on the server under `requestId`. */
export async function answerSamlSignIn(context: TenantAuthContext, requestId: string) {
  const response = await apiClient.post<SamlFormPostResponse>(
    `${getTenantEndpoint(context)}/saml/sso/answer`,
    { request: requestId },
  );

  return toSamlFormPost(response.data);
}

/** Signs the signed-in person in to a SAML app, from a link such as an app tile. */
export async function signInToSamlApp(context: TenantAuthContext, appId: string) {
  const response = await apiClient.post<SamlFormPostResponse>(
    `${getTenantEndpoint(context)}/saml/apps/${encodeURIComponent(appId)}/sign-in`,
  );

  return toSamlFormPost(response.data);
}

export async function answerSamlAppLogout(context: TenantAuthContext, message: SamlMessage) {
  const response = await apiClient.post<SamlFormPostResponse>(
    `${getTenantEndpoint(context)}/saml/slo/answer`,
    toSamlMessageRequest(message),
  );

  return toSamlFormPost(response.data);
}

export async function answerConnectionSamlLogout(
  context: TenantAuthContext,
  connectionId: string,
  message: SamlMessage,
) {
  const response = await apiClient.post<SamlFormPostResponse>(
    `${getTenantEndpoint(context)}/federation/connections/${encodeURIComponent(connectionId)}/saml/slo/answer`,
    toSamlMessageRequest(message),
  );

  return toSamlFormPost(response.data);
}

/** Posts the app's authorization request as it arrived, with the person's consent. */
export async function submitOAuthConsent(
  context: TenantAuthContext,
  request: Record<string, string>,
  consent: 'given' | 'not_asked_yet',
): Promise<AuthorizeOutcome> {
  const { data } = await apiClient.post<AuthorizeResponse>(
    `${getTenantEndpoint(context)}/oauth/authorize`,
    { ...request, consent },
  );

  switch (data.outcome) {
    case 'consent':
      return { kind: 'consent', scopes: data.scopes ?? [] };
    case 'sign_in':
      return { kind: 'sign_in' };
    default:
      return {
        formPost: data.form_post ?? null,
        kind: data.outcome,
        redirectTo: data.redirect_to ?? null,
      };
  }
}

/** Ends the session an app asked to end, when the person's session allows it. */
export async function endOAuthSession(
  context: TenantAuthContext,
  request: Record<string, string>,
  confirmed: boolean,
): Promise<EndSessionOutcome> {
  const { data } = await apiClient.post<EndSessionResponse>(
    `${getTenantEndpoint(context)}/oauth/end-session`,
    { ...request, confirmed },
  );

  return {
    frontChannelLogoutUris: data.front_channel_logout_uris,
    outcome: data.outcome,
    redirectTo: data.redirect_to ?? null,
  };
}

/** Mails or texts the code a password reset asks for. */
export async function requestPasswordResetCode(context: TenantAuthContext, token: string) {
  await apiClient.post<unknown>(`${getTenantEndpoint(context)}/auth/password/reset-code`, {
    token,
  });
}
