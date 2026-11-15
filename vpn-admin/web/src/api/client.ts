import axios from 'axios'
import { ElMessage } from 'element-plus'

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  timeout: 15000,
})

api.interceptors.request.use((config) => {
  const csrf = sessionStorage.getItem('vpn_admin_csrf')
  if (csrf) {
    config.headers['X-CSRF-Token'] = csrf
  }
  return config
})

api.interceptors.response.use(
  (response) => {
    if (response.headers?.['x-policy-refresh'] === 'failed') {
      ElMessage.warning('策略已保存，但在线会话刷新失败，将在下次连接时生效')
    }
    if (response.headers?.['x-policy-kick'] === 'failed') {
      ElMessage.warning('策略已保存，但用户下线失败，将在下次连接时生效')
    }
    return response
  },
  (error) => {
    if (
      error.response?.status === 401 &&
      window.location.pathname !== '/login'
    ) {
      sessionStorage.removeItem('vpn_admin_csrf')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)