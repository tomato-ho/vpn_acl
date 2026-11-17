<script setup lang="ts">
import { ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../../api/client'
import { apiErrorMessage } from '../../api/errors'
import type { AccessLogRow, AccessLogStats } from '../../types'
import { formatBytes } from '../../utils/format'

const props = defineProps<{
  modelValue: boolean
  sessionId?: string
  username?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [boolean] }>()

const loading = ref(false)
const items = ref<AccessLogRow[]>([])
const stats = ref<AccessLogStats | null>(null)

function close() {
  emit('update:modelValue', false)
}

async function load() {
  loading.value = true
  try {
    if (props.sessionId) {
      const response = await api.get<{
        items: AccessLogRow[]
        stats: AccessLogStats
      }>(`/sessions/${encodeURIComponent(props.sessionId)}/access`, {
        params: { page_size: 200 },
      })
      items.value = response.data.items
      stats.value = response.data.stats
    } else {
      // 老历史会话没有 session_id：退化为按用户名查询。
      const response = await api.get<{
        items: AccessLogRow[]
        stats: AccessLogStats
      }>('/access', {
        params: {
          username: props.username ?? '',
          range: 'all',
          page_size: 200,
        },
      })
      items.value = response.data.items
      stats.value = response.data.stats
    }
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      load()
    }
  },
)

function actionType(action: string): 'success' | 'danger' {
  return action === 'deny' ? 'danger' : 'success'
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    title="访问记录"
    width="900px"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div v-if="stats" class="access-summary muted">
      目标 {{ stats.targets }} 个 · 记录 {{ stats.records }} 条 · 上行
      {{ formatBytes(stats.bytes_up) }} · 下行
      {{ formatBytes(stats.bytes_down) }}
    </div>
    <el-table v-loading="loading" :data="items" stripe max-height="480">
      <el-table-column prop="dest_ip" label="目标 IP" min-width="140" />
      <el-table-column label="结果" width="90">
        <template #default="{ row }">
          <el-tag :type="actionType(row.action)" size="small">
            {{ row.action === 'deny' ? '拒绝' : '允许' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="上行" width="110">
        <template #default="{ row }">{{ formatBytes(row.bytes_up) }}</template>
      </el-table-column>
      <el-table-column label="下行" width="110">
        <template #default="{ row }">
          {{ formatBytes(row.bytes_down) }}
        </template>
      </el-table-column>
      <el-table-column prop="first_seen" label="首次访问" min-width="160" />
      <el-table-column prop="last_seen" label="最后访问" min-width="160" />
    </el-table>
    <template #footer>
      <el-button @click="close">关闭</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.access-summary {
  margin-bottom: 12px;
}
</style>