import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIState {
  // Sidebar state
  sidebarCollapsed: boolean;
  sidebarOpen: boolean; // For mobile overlay
  expandedSections: string[];

  // Actions
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarOpen: (open: boolean) => void;
  toggleSection: (section: string) => void;
  setExpandedSections: (sections: string[]) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false, // Expanded by default
      sidebarOpen: false,
      expandedSections: ['featured', 'recon'], // Featured and Recon expanded by default

      toggleSidebar: () =>
        set((state) => ({
          sidebarCollapsed: !state.sidebarCollapsed,
        })),

      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

      setSidebarOpen: (open) => set({ sidebarOpen: open }),

      toggleSection: (section) =>
        set((state) => ({
          expandedSections: state.expandedSections.includes(section)
            ? state.expandedSections.filter((s) => s !== section)
            : [...state.expandedSections, section],
        })),

      setExpandedSections: (sections) => set({ expandedSections: sections }),
    }),
    {
      name: 'heroforge-ui-storage',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        expandedSections: state.expandedSections,
      }),
    }
  )
);
