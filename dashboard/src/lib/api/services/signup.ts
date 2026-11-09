import { apiClient } from '@/lib/api/client';
import { createResource } from '@/lib/api/crud';

export type SignupPayload = {
  admin_email: string;
  admin_password: string;
  company_name: string;
  tenant_name: string;
  admin_display_name: string;
};

type SignupAcceptedResponse = {
  status: string;
};

type ConfirmSignupResponse = {
  org_slug: string;
  tenant_slug: string;
};

type ConfirmSignupRequest = {
  token: string;
};

/** Whether this deployment takes signups; a self-hosted installation does not. */
export async function isSignupOpen(): Promise<boolean> {
  const response = await apiClient.get<{ open: boolean }>('/signup');

  return response.data.open;
}

/** Mails a confirmation link; nothing is created until it is followed. */
export function signup(payload: SignupPayload) {
  return createResource<SignupAcceptedResponse, SignupPayload>('/signup', payload);
}

/** Creates the organization the mailed link was sent for. */
export function confirmSignup(token: string) {
  return createResource<ConfirmSignupResponse, ConfirmSignupRequest>('/signup/confirm', { token });
}
