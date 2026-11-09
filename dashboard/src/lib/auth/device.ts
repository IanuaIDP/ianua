const DEVICE_ID_STORAGE_KEY = 'ianua.device-id';

const BROWSER_NAMES: [RegExp, string][] = [
  [/Edg\//, 'Edge'],
  [/OPR\//, 'Opera'],
  [/Firefox\//, 'Firefox'],
  [/Chrome\//, 'Chrome'],
  [/Safari\//, 'Safari'],
];

const PLATFORM_NAMES: [RegExp, string][] = [
  [/Windows/, 'Windows'],
  [/Android/, 'Android'],
  [/iPhone|iPad|iPod/, 'iOS'],
  [/Mac OS X/, 'macOS'],
  [/Linux/, 'Linux'],
];

/**
 * Reads this browser's device id, creating one on first use.
 *
 * The id is a random value rather than a profile built from screen size and
 * user agent: two identical laptops out of the same box must not look like the
 * same device. Clearing site data forgets the device, which is the point —
 * the user gets challenged again rather than staying silently recognized.
 *
 * Returns `undefined` when storage is unavailable, which private browsing and
 * blocked third-party storage both cause.
 */
function readDeviceId(): string | undefined {
  try {
    const stored = window.localStorage.getItem(DEVICE_ID_STORAGE_KEY);

    if (stored) {
      return stored;
    }

    const created = window.crypto.randomUUID();
    window.localStorage.setItem(DEVICE_ID_STORAGE_KEY, created);

    return created;
  } catch {
    return undefined;
  }
}

function toHex(digest: ArrayBuffer): string {
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function findName(candidates: [RegExp, string][], userAgent: string): string | undefined {
  return candidates.find(([pattern]) => pattern.test(userAgent))?.[1];
}

/**
 * Hashes this browser's device id for the server to match against.
 *
 * Returns `undefined` when there is nothing trustworthy to send — no window,
 * no Web Crypto (which needs a secure context), or no usable storage. Every
 * one of those means the same thing to the server as an unrecognized device:
 * challenge the user. Sign-in still works, it just never takes the fast path.
 */
export async function getDeviceFingerprint(): Promise<string | undefined> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    return undefined;
  }

  const deviceId = readDeviceId();

  if (!deviceId) {
    return undefined;
  }

  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(deviceId));

  return toHex(digest);
}

/**
 * Names this device the way it will read in the user's device list, so they
 * can tell their own laptop from a session they don't recognize.
 *
 * The patterns are ordered most to least specific: Edge and Opera both claim
 * to be Chrome, Chrome claims to be Safari, and Android claims to be Linux.
 */
export function getDeviceName(): string {
  if (typeof navigator === 'undefined') {
    return 'Unknown device';
  }

  const browser = findName(BROWSER_NAMES, navigator.userAgent);
  const platform = findName(PLATFORM_NAMES, navigator.userAgent);

  if (browser && platform) {
    return `${browser} on ${platform}`;
  }

  return browser ?? platform ?? 'Unknown device';
}
