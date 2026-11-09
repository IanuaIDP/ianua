import axios, { type InternalAxiosRequestConfig } from 'axios';

import { withSignInReturn } from '@/lib/auth/sign-in-return';
import { getTenantPath } from '@/utils/dashboard-routes';
import { useAuthStore } from '@/store/auth-store';
import { getTenantRouteContext } from '@/utils/dashboard-routes';

type RetryableRequestConfig = InternalAxiosRequestConfig & { _retry401?: boolean };

export const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

function redirectToLogin() {
  if (typeof window === 'undefined') {
    return;
  }

  const tenantContext = getTenantRouteContext(window.location.pathname);
  const loginPath = tenantContext
    ? `${getTenantPath(tenantContext.orgSlug, tenantContext.tenantSlug)}/login`
    : '/login';

  if (window.location.pathname !== loginPath) {
    window.location.assign(
      withSignInReturn(loginPath, window.location.pathname, window.location.search),
    );
  }
}

apiClient.interceptors.request.use(
  (config) => {
    const accessToken = useAuthStore.getState().accessToken;

    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  },
);

apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    if (!axios.isAxiosError(error) || error.response?.status !== 401) {
      return Promise.reject(error);
    }

    const originalRequest = error.config as RetryableRequestConfig | undefined;

    if (!originalRequest || !originalRequest.headers?.Authorization) {
      return Promise.reject(error);
    }

    if (originalRequest._retry401) {
      useAuthStore.getState().logout();
      redirectToLogin();
      return Promise.reject(error);
    }

    originalRequest._retry401 = true;

    try {
      return await apiClient(originalRequest);
    } catch (retryError) {
      if (axios.isAxiosError(retryError) && retryError.response?.status === 401) {
        useAuthStore.getState().logout();
        redirectToLogin();
      }

      return Promise.reject(retryError);
    }
  },
);
