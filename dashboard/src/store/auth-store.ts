'use client';

import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

import type { Access, AuthState, LoginResponse, User } from '@/types/auth';

type TokenPair = Pick<LoginResponse, 'accessToken'>;

type AuthActions = {
  login: (response: LoginResponse) => void;
  logout: () => void;
  hydrate: () => void;
  setAccess: (access: Access | null) => void;
  setTokens: (tokens: TokenPair) => void;
  updateUser: (updates: Partial<User>) => void;
};

const initialAuthState: AuthState = {
  access: null,
  user: null,
  accessToken: null,
  isAuthenticated: false,
  isHydrated: false,
};

export const useAuthStore = create<AuthState & AuthActions>()(
  persist(
    (set, get) => ({
      ...initialAuthState,
      login: ({ access, accessToken, user }) => {
        set({
          access,
          accessToken,
          user,
          isAuthenticated: true,
        });
      },
      logout: () => {
        set({ ...initialAuthState, isHydrated: true });
      },
      hydrate: () => {
        set({ isHydrated: true });
      },
      setAccess: (access) => {
        set({ access });
      },
      setTokens: ({ accessToken }) => {
        set({
          accessToken,
          isAuthenticated: Boolean(accessToken && get().user),
        });
      },
      updateUser: (updates) => {
        const currentUser = get().user;

        if (!currentUser) {
          return;
        }

        set({ user: { ...currentUser, ...updates } });
      },
    }),
    {
      name: 'ianua-auth',
      onRehydrateStorage: () => (state) => {
        state?.hydrate();
      },
      partialize: (state) => ({
        access: state.access,
        accessToken: state.accessToken,
        isAuthenticated: state.isAuthenticated,
        user: state.user,
      }),
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
