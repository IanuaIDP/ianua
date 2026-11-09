import type { WaitingSignIn } from '@/lib/api/services/auth';

const WAITING_SIGN_IN_STORAGE_KEY = 'ianua-waiting-sign-in';

/** Keeps a sign-in for the tab the mailed link opens in. */
export function saveWaitingSignIn(waiting: WaitingSignIn) {
  try {
    window.localStorage.setItem(WAITING_SIGN_IN_STORAGE_KEY, JSON.stringify(waiting));
  } catch {
    // Without storage the link cannot find this sign-in and says so.
  }
}

export function readWaitingSignIn(): WaitingSignIn | null {
  try {
    const stored = window.localStorage.getItem(WAITING_SIGN_IN_STORAGE_KEY);

    return stored ? (JSON.parse(stored) as WaitingSignIn) : null;
  } catch {
    return null;
  }
}

export function clearWaitingSignIn() {
  try {
    window.localStorage.removeItem(WAITING_SIGN_IN_STORAGE_KEY);
  } catch {
    // Nothing was kept.
  }
}
