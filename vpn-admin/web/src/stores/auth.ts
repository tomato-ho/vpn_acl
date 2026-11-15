import { defineStore } from 'pinia'
import { api } from '../api/client'

export interface Me {
  username: string
  csrf_token: string
  expires_at: number
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    username: '',
    csrf: '',
    expiresAt: 0,
    loaded: false,
  }),
  getters: {
    isAuthenticated: (state) => Boolean(state.username),
  },
  actions: {
    setMe(me: Me) {
      this.username = me.username
      this.csrf = me.csrf_token
      this.expiresAt = me.expires_at
      this.loaded = true
      sessionStorage.setItem('vpn_admin_csrf', me.csrf_token)
    },
    clear() {
      this.username = ''
      this.csrf = ''
      this.expiresAt = 0
      this.loaded = true
      sessionStorage.removeItem('vpn_admin_csrf')
    },
    async login(username: string, password: string) {
      const { data } = await api.post<Me>('/login', { username, password })
      this.setMe(data)
    },
    async fetchMe() {
      try {
        const { data } = await api.get<Me>('/me')
        this.setMe(data)
        return true
      } catch {
        this.clear()
        return false
      }
    },
    async logout() {
      try {
        await api.post('/logout')
      } finally {
        this.clear()
      }
    },
  },
})