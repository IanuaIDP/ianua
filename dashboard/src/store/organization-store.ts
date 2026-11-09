'use client';

import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

import type { Organization } from '@/types/organization';

type OrganizationState = {
  organization: Organization | null;
};

type OrganizationActions = {
  clearOrganization: () => void;
  setOrganization: (organization: Organization) => void;
};

const initialOrganizationState: OrganizationState = {
  organization: null,
};

export const useOrganizationStore = create<OrganizationState & OrganizationActions>()(
  persist(
    (set) => ({
      ...initialOrganizationState,
      clearOrganization: () => set(initialOrganizationState),
      setOrganization: (organization) => set({ organization }),
    }),
    {
      name: 'ianua-organization',
      partialize: (state) => ({
        organization: state.organization,
      }),
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
