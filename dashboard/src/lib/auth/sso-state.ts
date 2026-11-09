const SSO_STATE_STORAGE_KEY = 'ianua-sso-state';

/** The address that starts a single sign-on, with a fresh value to bring back to its last step. */
export function withSsoState(startHref: string) {
  const state = crypto.randomUUID();

  try {
    window.sessionStorage.setItem(SSO_STATE_STORAGE_KEY, state);
  } catch {
    // Without storage the sign-on is refused at its last step and says so.
  }

  return `${startHref}?state=${encodeURIComponent(state)}`;
}

/** The value kept when this tab started its single sign-on. */
export function readSsoState() {
  try {
    return window.sessionStorage.getItem(SSO_STATE_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}
