import { createResource, getList } from '@/lib/api/crud';
import type { TenantAuthContext } from '@/lib/api/services/auth';
import { getDeviceFingerprint, getDeviceName } from '@/lib/auth/device';
import type { DeviceState, DeviceStatus, TrustedDevice } from '@/types/device';
import { formatBackendDate } from '@/utils/date';

type DeviceResponse = {
  created_at: string;
  id: string;
  name: string;
  status: DeviceState;
};

type DeviceListResponse = {
  devices: DeviceResponse[];
};

type RevokeDeviceRequest = {
  device_id: string;
};

type TrustDeviceRequest = {
  device_name: string;
  fingerprint_hash: string;
};

const statusByState: Record<DeviceState, DeviceStatus> = {
  revoked: 'Revoked',
  trusted: 'Trusted',
};

function getTenantAuthEndpoint(context: TenantAuthContext, actionPath: string) {
  return `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
    context.tenantSlug,
  )}/auth/${actionPath}`;
}

function getOrgDevicesEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/devices`;
}

function toTrustedDevice(response: DeviceResponse): TrustedDevice {
  return {
    created: formatBackendDate(response.created_at),
    id: response.id,
    name: response.name,
    status: statusByState[response.status] ?? 'Revoked',
  };
}

export async function getTrustedDevices(context: TenantAuthContext): Promise<TrustedDevice[]> {
  const response = await getList<DeviceListResponse>(
    getTenantAuthEndpoint(context, 'device/trust'),
  );

  return response.devices.map(toTrustedDevice);
}

/**
 * Trusts the browser this is running in, so the next sign-in from it can skip
 * the second factor.
 *
 * Deliberately never throws. It runs once the session already exists, so the
 * user is signed in either way — failing here should cost them the fast path
 * next time, not the sign-in they just completed. It is also a no-op on a
 * browser with no usable fingerprint, since the server would have nothing to
 * match the device against.
 */
async function trustThisBrowser(endpoint: string): Promise<void> {
  const fingerprintHash = await getDeviceFingerprint();

  if (!fingerprintHash) {
    return;
  }

  try {
    await createResource<unknown, TrustDeviceRequest>(endpoint, {
      device_name: getDeviceName(),
      fingerprint_hash: fingerprintHash,
    });
  } catch {
    // See above: a device the server refused to remember is not a failed login.
  }
}

/** Trusts this browser for a workspace user. */
export async function trustCurrentDevice(context: TenantAuthContext): Promise<void> {
  await trustThisBrowser(getTenantAuthEndpoint(context, 'device/trust/add'));
}

/** Trusts this browser for an organization administrator. */
export async function trustCurrentOrgDevice(orgSlug: string): Promise<void> {
  await trustThisBrowser(getOrgDevicesEndpoint(orgSlug));
}

export async function revokeTrustedDevice(
  context: TenantAuthContext,
  deviceId: string,
): Promise<void> {
  await createResource<unknown, RevokeDeviceRequest>(
    getTenantAuthEndpoint(context, 'device/trust/revoke'),
    { device_id: deviceId },
  );
}

export async function getOrgTrustedDevices(orgSlug: string): Promise<TrustedDevice[]> {
  const response = await getList<DeviceListResponse>(getOrgDevicesEndpoint(orgSlug));

  return response.devices.map(toTrustedDevice);
}

export async function revokeOrgTrustedDevice(orgSlug: string, deviceId: string): Promise<void> {
  await createResource<unknown, RevokeDeviceRequest>(`${getOrgDevicesEndpoint(orgSlug)}/revoke`, {
    device_id: deviceId,
  });
}
