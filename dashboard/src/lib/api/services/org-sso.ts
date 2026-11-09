import { apiClient } from '@/lib/api/client';
import { toOrgLoginResult, type LoginResult, type OrgLoginResponse } from '@/lib/api/services/auth';

export type OrgSsoAnswer =
  | { code: string; protocol: 'oidc'; state: string }
  | { protocol: 'saml'; relay_state: string; saml_response: string };

type OrgSsoStartResponse = {
  binding: string;
  redirect_url: string;
};

/** Starts a dashboard sign-in through the organization's identity provider. */
export async function startOrganizationSso(organization: string) {
  const { data } = await apiClient.post<OrgSsoStartResponse>('/login/sso', { organization });

  return { binding: data.binding, redirectUrl: data.redirect_url };
}

export async function finishOrganizationSso(
  binding: string,
  answer: OrgSsoAnswer,
): Promise<LoginResult> {
  const { data } = await apiClient.post<OrgLoginResponse>('/login/sso/callback', {
    answer,
    binding,
  });

  return toOrgLoginResult('', data);
}
