<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  Connection,
  DataLine,
  Document,
  Monitor,
  Odometer,
  Setting,
  User,
  UserFilled,
  View,
} from '@element-plus/icons-vue'
import { useAuthStore } from '../stores/auth'
import { useBrandingStore } from '../stores/branding'
import ChangePasswordDialog from '../components/ChangePasswordDialog.vue'

const router = useRouter()
const auth = useAuthStore()
const branding = useBrandingStore()
const showPassword = ref(false)

async function logout() {
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <el-container class="admin-shell">
    <el-aside width="220px" class="admin-aside">
      <div class="admin-brand">
        <img
          v-if="branding.logoUrl"
          :src="branding.logoUrl"
          class="brand-logo"
          alt=""
        />
        <span>{{ branding.brandTitle }}</span>
      </div>
      <el-menu :default-active="$route.path" router>
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon>
          <span>Dashboard</span>
        </el-menu-item>
        <el-menu-item index="/users">
          <el-icon><User /></el-icon>
          <span>用户管理</span>
        </el-menu-item>
        <el-menu-item index="/groups">
          <el-icon><UserFilled /></el-icon>
          <span>组管理</span>
        </el-menu-item>
        <el-menu-item index="/services">
          <el-icon><Connection /></el-icon>
          <span>服务管理</span>
        </el-menu-item>
        <el-menu-item index="/sessions">
          <el-icon><Monitor /></el-icon>
          <span>在线会话</span>
        </el-menu-item>
        <el-menu-item index="/access">
          <el-icon><View /></el-icon>
          <span>访问审计</span>
        </el-menu-item>
        <el-menu-item index="/audit">
          <el-icon><Document /></el-icon>
          <span>审计日志</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>设置</span>
        </el-menu-item>
        <el-menu-item index="/metrics">
          <el-icon><DataLine /></el-icon>
          <span>Metrics</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="admin-header">
        <div class="admin-title">{{ branding.brandName }}</div>
        <div>
          <span class="muted">{{ auth.username }}</span>
          <el-button link type="primary" @click="showPassword = true">
            修改密码
          </el-button>
          <el-button link type="primary" @click="logout">退出</el-button>
        </div>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>

    <ChangePasswordDialog v-model="showPassword" />
  </el-container>
</template>

<style scoped>
.admin-shell {
  height: 100vh;
}

.admin-aside {
  background: #ffffff;
  border-right: 1px solid #e4e7ed;
}

.admin-brand {
  height: 60px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 16px;
  font-weight: 700;
  font-size: 16px;
  color: #1e3a5f;
  border-bottom: 1px solid #e4e7ed;
}

.brand-logo {
  width: 30px;
  height: 30px;
  object-fit: contain;
  flex: none;
}
</style>