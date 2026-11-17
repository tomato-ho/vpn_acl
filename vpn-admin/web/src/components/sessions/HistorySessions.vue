<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../../api/client'
import { downloadCsv } from '../../api/csv'
import { apiErrorMessage } from '../../api/errors'
import type { HistorySession, SessionHistoryStats } from '../../types'
import { formatBytes, formatDuration } from '../../utils/format'
import AccessLogDialog from './AccessLogDialog.vue'

const range = ref('today')
const customRange = ref<[string, string] | null>(null)
const username = ref('')
const includeDeleted = ref(true)
const page = ref(1)
const pageSize = ref(50)
const loading = ref(false)
const items = ref<HistorySession[]>([])
const total = ref(0)
const stats = ref<SessionHistoryStats | null>(null)
const accessOpen = ref(false)
const accessSessionId = ref('')

function buildParams(withPage: boolean): Record<string, unknown> {
  const params: Record<string, unknown> = {
    range: range.value,
    username: username.value,
    include_deleted: includeDeleted.value ? 1 : 0,
  }
  if (range.value === 'custom' && customRange.value) {
    params.from = customRange.value[0]
    params.to = customRange.value[1]
  }
  if (withPage) {
    params.page = page.value
    params.page_size = pageSize.value
  }
  return params
}

function validateFilters(): boolean {
  if (range.value === 'custom' && !customRange.value) {
    ElMessage.warning('请选择自定义日期范围')
    return false
  }
  return true
}

async function load() {
  if (!validateFilters()) {
    return
  }
  loading.value = true
  try {
    const [historyResponse, statsResponse] = await Promise.all([
      api.get<{
        items: HistorySession[]
        total: number
        page: number
        page_size: number
      }>('/sessions/history', { params: buildParams(true) }),
      api.get<SessionHistoryStats>('/sessions/history/stats', {
        params: buildParams(false),
      }),
    ])
    items.value = historyResponse.data.items
    total.value = historyResponse.data.total
    stats.value = statsResponse.data
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  load()
}

function changePage(value: number) {
  page.value = value
  load()
}

function changePageSize(value: number) {
  pageSize.value = value
  page.value = 1
  load()
}

async function exportCsv() {
  if (!validateFilters()) {
    return
  }
  try {
    await downloadCsv(
      '/sessions/history/export',
      buildParams(false),
      'vpn-sessions.csv',
    )
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function stateLabel(state: string): string {
  if (state === 'online') return '在线'
  if (state === 'closed') return '已结束'
  return '计费滞留'
}

function stateType(state: string): 'success' | 'info' | 'warning' {
  if (state === 'online') return 'success'
  if (state === 'closed') return 'info'
  return 'warning'
}

function showAccess(row: unknown) {
  const session = row as HistorySession
  accessSessionId.value = session.session_id ?? ''
  accessOpen.value = true
}

onMounted(load)
</script>

<template>
  <div v-loading="loading">
    <el-row :gutter="16" class="stat-grid">
      <el-col :span="5">
        <el-card>
          <div class="muted">唯一用户</div>
          <h2>{{ stats?.unique_users ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">会话数</div>
          <h2>{{ stats?.session_count ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">当前在线</div>
          <h2>{{ stats?.online_sessions ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">总时长</div>
          <h2>{{ formatDuration(stats?.total_seconds ?? 0) }}</h2>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card>
          <div class="muted">总流量</div>
          <h2>
            {{ formatBytes((stats?.bytes_in ?? 0) + (stats?.bytes_out ?? 0)) }}
          </h2>
        </el-card>
      </el-col>
    </el-row>

    <div class="toolbar">
      <el-select v-model="range" style="width: 130px" @change="search">
        <el-option label="今天" value="today" />
        <el-option label="24 小时" value="24h" />
        <el-option label="7 天" value="7d" />
        <el-option label="30 天" value="30d" />
        <el-option label="自定义" value="custom" />
      </el-select>
      <el-date-picker
        v-if="range === 'custom'"
        v-model="customRange"
        type="daterange"
        value-format="YYYY-MM-DD"
        start-placeholder="开始日期"
        end-placeholder="结束日期"
        @change="search"
      />
      <el-input
        v-model="username"
        placeholder="用户名搜索"
        clearable
        style="width: 200px"
        @keyup.enter="search"
      />
      <el-switch v-model="includeDeleted" active-text="含已删除用户" @change="search" />
      <el-button type="primary" @click="search">查询</el-button>
      <el-button @click="exportCsv">导出 CSV</el-button>
    </div>

    <el-card>
      <el-table :data="items" stripe>
        <el-table-column prop="username" label="用户" min-width="120" />
        <el-table-column label="用户状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.user_exists ? 'success' : 'info'">
              {{ row.user_exists ? '当前' : '已删除' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="virtual_ip" label="隧道 IP" width="130" />
        <el-table-column prop="remote_ip" label="来源 IP" min-width="140" />
        <el-table-column prop="start_time" label="开始时间" min-width="180" />
        <el-table-column prop="stop_time" label="结束时间" min-width="180" />
        <el-table-column label="时长" width="110">
          <template #default="{ row }">
            {{ formatDuration(row.duration_seconds) }}
          </template>
        </el-table-column>
        <el-table-column label="流量" width="130">
          <template #default="{ row }">
            {{ formatBytes(row.bytes_in + row.bytes_out) }}
          </template>
        </el-table-column>
        <el-table-column prop="terminate_cause" label="结束原因" min-width="130" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="stateType(row.state)">
              {{ stateLabel(row.state) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.session_id"
              link
              type="primary"
              @click="showAccess(row)"
            >
              访问记录
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :page-sizes="[20, 50, 100, 200]"
          :total="total"
          layout="total, sizes, prev, pager, next"
          @current-change="changePage"
          @size-change="changePageSize"
        />
      </div>
    </el-card>

    <AccessLogDialog
      v-model="accessOpen"
      :session-id="accessSessionId"
    />
  </div>
</template>