<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'

interface DashboardData {
  users: { total: number; enabled: number; disabled: number }
  groups: number
  active_sessions: number
  audit_entries: number
  policy_version: number
  auth: { accept: number; reject: number }
}

interface MetricsResponse {
  dashboard: DashboardData
  database_up: boolean
  policyd_up: boolean
}

const data = ref<DashboardData | null>(null)
const databaseUp = ref(false)
const policydUp = ref(false)
const loading = ref(false)
let timer: number | undefined

async function load() {
  loading.value = true
  try {
    const response = await api.get<MetricsResponse>('/metrics')
    data.value = response.data.dashboard
    databaseUp.value = response.data.database_up
    policydUp.value = response.data.policyd_up
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = window.setInterval(load, 15000)
})

onBeforeUnmount(() => {
  if (timer) {
    window.clearInterval(timer)
  }
})
</script>

<template>
  <div v-loading="loading">
    <div class="page-header">
      <div class="page-title">Dashboard</div>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-row :gutter="16" class="stat-grid">
      <el-col :span="6">
        <el-card>
          <div class="muted">在线会话</div>
          <h2>{{ data?.active_sessions ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">启用用户</div>
          <h2>{{ data?.users.enabled ?? 0 }}</h2>
          <div class="muted">总用户 {{ data?.users.total ?? 0 }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">组数量</div>
          <h2>{{ data?.groups ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">策略版本</div>
          <h2>{{ data?.policy_version ?? 0 }}</h2>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" class="stat-grid">
      <el-col :span="8">
        <el-card>
          <div class="muted">认证成功</div>
          <h2>{{ data?.auth.accept ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="muted">认证失败</div>
          <h2>{{ data?.auth.reject ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="muted">服务状态</div>
          <div class="status-row">
            <el-tag :type="databaseUp ? 'success' : 'danger'">
              数据库 {{ databaseUp ? '正常' : '异常' }}
            </el-tag>
            <el-tag :type="policydUp ? 'success' : 'danger'">
              policyd {{ policydUp ? '正常' : '异常' }}
            </el-tag>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.status-row {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}
</style>