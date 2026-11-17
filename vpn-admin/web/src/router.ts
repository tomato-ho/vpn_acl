import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('./views/Login.vue'),
    },
    {
      path: '/',
      component: () => import('./layouts/AdminLayout.vue'),
      children: [
        { path: '', redirect: '/dashboard' },
        {
          path: 'dashboard',
          name: 'dashboard',
          component: () => import('./views/Dashboard.vue'),
        },
        {
          path: 'users',
          name: 'users',
          component: () => import('./views/Users.vue'),
        },
        {
          path: 'groups',
          name: 'groups',
          component: () => import('./views/Groups.vue'),
        },
        {
          path: 'services',
          name: 'services',
          component: () => import('./views/Services.vue'),
        },
        {
          path: 'sessions',
          name: 'sessions',
          component: () => import('./views/Sessions.vue'),
        },
        {
          path: 'access',
          name: 'access',
          component: () => import('./views/Access.vue'),
        },
        {
          path: 'audit',
          name: 'audit',
          component: () => import('./views/Audit.vue'),
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('./views/Settings.vue'),
        },
        {
          path: 'metrics',
          name: 'metrics',
          component: () => import('./views/Metrics.vue'),
        },
      ],
    },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  if (to.path === '/login') {
    if (auth.isAuthenticated) {
      return '/dashboard'
    }
    return true
  }
  if (!auth.loaded) {
    await auth.fetchMe()
  }
  if (!auth.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  return true
})

export default router