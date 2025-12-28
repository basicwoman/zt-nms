import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Identity } from '@/types/api'

interface AuthState {
  token: string | null
  identity: Identity | null
  isAuthenticated: boolean
  login: (token: string, identity: Identity) => void
  logout: () => void
  updateIdentity: (identity: Identity) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      identity: null,
      isAuthenticated: false,
      login: (token, identity) =>
        set({
          token,
          identity,
          isAuthenticated: true,
        }),
      logout: () =>
        set({
          token: null,
          identity: null,
          isAuthenticated: false,
        }),
      updateIdentity: (identity) => set({ identity }),
    }),
    {
      name: 'zt-nms-auth',
      partialize: (state) => ({
        token: state.token,
        identity: state.identity,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
