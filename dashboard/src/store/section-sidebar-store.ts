import { create } from 'zustand';

type SectionSidebarStore = {
  expandedGroupByKey: Record<string, string | null>;
  setExpandedGroup: (key: string, group: string | null) => void;
};

export const useSectionSidebarStore = create<SectionSidebarStore>((set) => ({
  expandedGroupByKey: {},
  setExpandedGroup: (key, group) =>
    set((state) => ({ expandedGroupByKey: { ...state.expandedGroupByKey, [key]: group } })),
}));
