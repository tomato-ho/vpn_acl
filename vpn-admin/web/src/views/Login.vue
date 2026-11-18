<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { apiErrorMessage } from '../api/errors'
import { useAuthStore } from '../stores/auth'
import { useBrandingStore } from '../stores/branding'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const branding = useBrandingStore()

const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    const redirect = route.query.redirect
    const target =
      typeof redirect === 'string' &&
      redirect.startsWith('/') &&
      !redirect.startsWith('//')
        ? redirect
        : '/dashboard'
    await router.push(target)
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <el-card class="login-card">
      <div class="login-title">
        <img
          v-if="branding.logoUrl"
          :src="branding.logoUrl"
          class="login-logo"
          alt=""
        />
        <h2>{{ branding.brandTitle }}</h2>
        <div class="muted">{{ branding.brandName }}</div>
      </div>
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="用户名">
          <el-input v-model="form.username" autocomplete="username" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="current-password"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button type="primary" :loading="loading" class="login-button" @click="submit">
          登录
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<style scoped>
.login-button {
  width: 100%;
}

.login-logo {
  display: block;
  width: 56px;
  height: 56px;
  margin: 0 auto 12px;
  object-fit: contain;
}
</style>