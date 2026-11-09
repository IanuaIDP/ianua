import type { OrgSsoAnswer } from '@/lib/api';

const BINDING_STORAGE_KEY = 'ianua-org-sso-binding';

export const ORG_SSO_SAML_ANSWER_STORAGE_KEY = 'ianua-org-sso-saml-answer';

/** Keeps the secret that ties this sign-in to this browser until it comes back. */
export function saveOrgSsoBinding(binding: string) {
  window.sessionStorage.setItem(BINDING_STORAGE_KEY, binding);
}

export function readOrgSsoBinding() {
  try {
    return window.sessionStorage.getItem(BINDING_STORAGE_KEY);
  } catch {
    return null;
  }
}

/** The SAML answer the identity provider posted here, kept out of the address. */
export function readOrgSsoSamlAnswer(): OrgSsoAnswer | null {
  try {
    const raw = window.sessionStorage.getItem(ORG_SSO_SAML_ANSWER_STORAGE_KEY);

    window.sessionStorage.removeItem(ORG_SSO_SAML_ANSWER_STORAGE_KEY);

    return raw ? (JSON.parse(raw) as OrgSsoAnswer) : null;
  } catch {
    return null;
  }
}
