import { create } from 'zustand';

type AppState = {
  isSidebarOpen: boolean;
};

type AppActions = {
  setSidebarOpen: (isSidebarOpen: boolean) => void;
  toggleSidebar: () => void;
};

type AppStore = AppState & AppActions;

export const useAppStore = create<AppStore>((set) => ({
  isSidebarOpen: true,
  setSidebarOpen: (isSidebarOpen) => set({ isSidebarOpen }),
  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
}));
