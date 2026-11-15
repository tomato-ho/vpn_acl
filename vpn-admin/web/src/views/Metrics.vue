<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import {
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
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

interface CurrentMetrics {
  dashboard: DashboardData
  database_up: boolean
  policyd_up: boolean
  radacct: { open: number; closed: number }
}

interface AuthPoint {
  bucket: string
  accept: number
  reject: number
}

interface SessionPoint {
  bucket: string
  started: number
  stopped: number
  session_time: number
  bytes_in: number
  bytes_out: number
}

interface TopUser {
  username: string
  sessions: number
  bytes_in: number
  bytes_out: number
  session_time: number
  user_exists: boolean
}

const range = ref('24h')
const step = ref('1h')
const includeDeleted = ref(false)
const loading = ref(false)
const current = ref<CurrentMetrics | null>(null)
const authPoints = ref<AuthPoint[]>([])
const sessionPoints = ref<SessionPoint[]>([])
const topUsers = ref<TopUser[]>([])

echarts.use([
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer,
])

const authRef = ref<HTMLDivElement | null>(null)
const sessionRef = ref<HTMLDivElement | null>(null)
const trafficRef = ref<HTMLDivElement | null>(null)

let authChart: ReturnType<typeof echarts.init> | null = null
let sessionChart: ReturnType<typeof echarts.init> | null = null
let trafficChart: ReturnType<typeof echarts.init> | null = null

function toMb(value: number): number {
  return Number((value / 1024 / 1024).toFixed(2))
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = value / 1024
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index += 1
  }
  return `${size.toFixed(2)} ${units[index]}`
}

function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`
}

function shortBucket(bucket: string): string {
  return bucket.slice(5, 16)
}

async function loadCurrent() {
  try {
    const response = await api.get<CurrentMetrics>('/metrics')
    current.value = response.data
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

async function loadHistory() {
  try {
    const response = await api.get<{
      auth: AuthPoint[]
      sessions: SessionPoint[]
    }>('/metrics/history', {
      params: { range: range.value, step: step.value },
    })
    authPoints.value = response.data.auth
    sessionPoints.value = response.data.sessions
    await nextTick()
    renderCharts()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

async function loadTopUsers() {
  try {
    const response = await api.get<{ items: TopUser[] }>(
      '/metrics/top-users',
      {
        params: {
          range: range.value,
          limit: 10,
          include_deleted: includeDeleted.value ? 1 : 0,
        },
      },
    )
    topUsers.value = response.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function renderCharts() {
  const buckets = authPoints.value.map((point) => shortBucket(point.bucket))

  if (authRef.value) {
    authChart = authChart ?? echarts.init(authRef.value)
    authChart.setOption(
      {
        tooltip: { trigger: 'axis' },
        legend: { data: ['成功', '失败'] },
        grid: { left: 40, right: 20, top: 40, bottom: 30 },
        xAxis: { type: 'category', data: buckets },
        yAxis: { type: 'value' },
        series: [
          {
            name: '成功',
            type: 'line',
            smooth: true,
            data: authPoints.value.map((point) => point.accept),
          },
          {
            name: '失败',
            type: 'line',
            smooth: true,
            data: authPoints.value.map((point) => point.reject),
          },
        ],
      },
      true,
    )
  }

  const sessionBuckets = sessionPoints.value.map((point) =>
    shortBucket(point.bucket),
  )
  if (sessionRef.value) {
    sessionChart = sessionChart ?? echarts.init(sessionRef.value)
    sessionChart.setOption(
      {
        tooltip: { trigger: 'axis' },
        legend: { data: ['新建', '结束'] },
        grid: { left: 40, right: 20, top: 40, bottom: 30 },
        xAxis: { type: 'category', data: sessionBuckets },
        yAxis: { type: 'value' },
        series: [
          {
            name: '新建',
            type: 'bar',
            data: sessionPoints.value.map((point) => point.started),
          },
          {
            name: '结束',
            type: 'bar',
            data: sessionPoints.value.map((point) => point.stopped),
          },
        ],
      },
      true,
    )
  }

  if (trafficRef.value) {
    trafficChart = trafficChart ?? echarts.init(trafficRef.value)
    trafficChart.setOption(
      {
        tooltip: { trigger: 'axis' },
        legend: { data: ['接收 MB', '发送 MB'] },
        grid: { left: 50, right: 20, top: 40, bottom: 30 },
        xAxis: { type: 'category', data: sessionBuckets },
        yAxis: { type: 'value' },
        series: [
          {
            name: '接收 MB',
            type: 'line',
            smooth: true,
            areaStyle: {},
            data: sessionPoints.value.map((point) => toMb(point.bytes_in)),
          },
          {
            name: '发送 MB',
            type: 'line',
            smooth: true,
            areaStyle: {},
            data: sessionPoints.value.map((point) => toMb(point.bytes_out)),
          },
        ],
      },
      true,
    )
  }
}

async function loadAll() {
  loading.value = true
  try {
    await Promise.all([loadCurrent(), loadHistory(), loadTopUsers()])
  } finally {
    loading.value = false
  }
}

watch([range, step], async () => {
  await Promise.all([loadHistory(), loadTopUsers()])
})

watch(includeDeleted, async () => {
  await loadTopUsers()
})

onMounted(loadAll)

onBeforeUnmount(() => {
  authChart?.dispose()
  sessionChart?.dispose()
  trafficChart?.dispose()
})
</script>

<template>
  <div v-loading="loading">
    <div class="page-header">
      <div class="page-title">Metrics</div>
      <div class="toolbar">
        <el-select v-model="range" style="width: 110px">
          <el-option label="24 小时" value="24h" />
          <el-option label="7 天" value="7d" />
          <el-option label="30 天" value="30d" />
        </el-select>
        <el-select v-model="step" style="width: 110px">
          <el-option label="1 小时" value="1h" />
          <el-option label="1 天" value="1d" />
        </el-select>
        <el-button @click="loadAll">刷新</el-button>
      </div>
    </div>

    <el-row :gutter="16" class="stat-grid">
      <el-col :span="6">
        <el-card>
          <div class="muted">在线会话</div>
          <h2>{{ current?.dashboard.active_sessions ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">启用用户</div>
          <h2>{{ current?.dashboard.users.enabled ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">未结束计费会话</div>
          <h2>{{ current?.radacct.open ?? 0 }}</h2>
          <div class="muted">已结束 {{ current?.radacct.closed ?? 0 }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card>
          <div class="muted">服务状态</div>
          <div class="status-row">
            <el-tag :type="current?.database_up ? 'success' : 'danger'">
              数据库 {{ current?.database_up ? '正常' : '异常' }}
            </el-tag>
            <el-tag :type="current?.policyd_up ? 'success' : 'danger'">
              policyd {{ current?.policyd_up ? '正常' : '异常' }}
            </el-tag>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16">
      <el-col :span="12">
        <el-card>
          <template #header>认证趋势</template>
          <div ref="authRef" class="chart" />
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>会话趋势</template>
          <div ref="sessionRef" class="chart" />
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="12">
        <el-card>
          <template #header>流量趋势</template>
          <div ref="trafficRef" class="chart" />
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="top-header">
              <span>Top 用户</span>
              <el-switch
                v-model="includeDeleted"
                active-text="显示已删除"
              />
            </div>
          </template>
          <el-table :data="topUsers" stripe max-height="320">
            <el-table-column prop="username" label="用户" min-width="120" />
            <el-table-column label="状态" width="90">
              <template #default="{ row }">
                <el-tag :type="row.user_exists ? 'success' : 'info'">
                  {{ row.user_exists ? '当前' : '已删除' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="sessions" label="会话数" width="90" />
            <el-table-column label="流量" min-width="130">
              <template #default="{ row }">
                {{ formatBytes(row.bytes_in + row.bytes_out) }}
              </template>
            </el-table-column>
            <el-table-column label="时长" width="100">
              <template #default="{ row }">
                {{ formatDuration(row.session_time) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.chart {
  height: 300px;
}

.top-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.status-row {
  display: flex;
  gap: 8px;
  margin-top: 12px;
  flex-wrap: wrap;
}
</style>