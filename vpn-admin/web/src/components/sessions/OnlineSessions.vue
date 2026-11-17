<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../../api/client'
import { apiErrorMessage } from '../../api/errors'
import AccessLogDialog from './AccessLogDialog.vue'

interface SessionRow {
  session_id: string
  username: string
  virtual_ip: string
  remote_ip: string
  start_time: string
  duration_seconds: number
  bytes_in: number
  bytes_out: number
  online: boolean
}

const items = ref<SessionRow[]>([])
const loading = ref(false)
const updatedAt = ref('')
const accessOpen = ref(false)
const accessSessionId = ref('')
const accessUsername = ref('')
let timer: number | undefined

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = value / 1024
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index += 1
  }
  return `${size.toFixed(1)} ${units[index]}`
}

function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const rest = seconds % 60
  if (hours > 0) return `${hours}h ${minutes}m ${rest}s`
  if (minutes > 0) return `${minutes}m ${rest}s`
  return `${rest}s`
}

async function load() {
  loading.value = true
  try {
    const response = await api.get<{ items: SessionRow[] }>('/sessions')
    items.value = response.data.items
    updatedAt.value = new Date().toLocaleTimeString()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

async function kick(row: unknown) {
  const session = row as SessionRow
  try {
    await ElMessageBox.confirm(
      `确定将用户 ${session.username} 强制下线？`,
      '强制下线',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.post(`/sessions/${encodeURI(session.username)}/kick`)
    ElMessage.success('已发送下线指令')
    window.setTimeout(load, 1500)
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function showAccess(row: unknown) {
  const session = row as SessionRow
  accessSessionId.value = session.session_id
  accessUsername.value = session.username
  accessOpen.value = true
}

onMounted(() => {
  load()
  timer = window.setInterval(load, 10000)
})

onBeforeUnmount(() => {
  if (timer) {
    window.clearInterval(timer)
  }
})
</script>

<template>
  <div>
    <div class="page-header">
      <div class="muted">更新于 {{ updatedAt }}</div>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-table v-loading="loading" :data="items" stripe>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.online ? 'success' : 'info'">
            {{ row.online ? '在线' : '离线' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="username" label="用户" min-width="140" />
      <el-table-column prop="virtual_ip" label="隧道 IP" width="140" />
      <el-table-column prop="remote_ip" label="来源 IP" min-width="150" />
      <el-table-column prop="start_time" label="连接时间" min-width="180" />
      <el-table-column label="时长" width="120">
        <template #default="{ row }">
          {{ formatDuration(row.duration_seconds) }}
        </template>
      </el-table-column>
      <el-table-column label="接收" width="130">
        <template #default="{ row }">{{ formatBytes(row.bytes_in) }}</template>
      </el-table-column>
      <el-table-column label="发送" width="130">
        <template #default="{ row }">{{ formatBytes(row.bytes_out) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="170" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="showAccess(row)">
            访问记录
          </el-button>
          <el-button link type="danger" @click="kick(row)">强制下线</el-button>
        </template>
      </el-table-column>
    </el-table>

    <AccessLogDialog
      v-model="accessOpen"
      :session-id="accessSessionId"
      :username="accessUsername"
    />
  </div>
</template>