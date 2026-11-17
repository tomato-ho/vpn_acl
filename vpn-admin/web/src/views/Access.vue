<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { downloadCsv } from '../api/csv'
import { apiErrorMessage } from '../api/errors'
import type { AccessLogRow, AccessLogStats } from '../types'
import { formatBytes } from '../utils/format'

const route = useRoute()

const range = ref('7d')
const customRange = ref<[string, string] | null>(null)
const username = ref('')
const destIp = ref('')
const destCidr = ref('')
const action = ref('')
const page = ref(1)
const pageSize = ref(50)
const loading = ref(false)
const items = ref<AccessLogRow[]>([])
const total = ref(0)
const stats = ref<AccessLogStats | null>(null)

function buildParams(withPage: boolean): Record<string, unknown> {
  const params: Record<string, unknown> = {
    range: range.value,
    username: username.value,
    dest_ip: destIp.value,
    dest_cidr: destCidr.value,
    action: action.value,
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
  if (destIp.value && destCidr.value) {
    ElMessage.warning('目标 IP 与目标网段只能填一个')
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
    const response = await api.get<{
      items: AccessLogRow[]
      total: number
      page: number
      page_size: number
      stats: AccessLogStats
    }>('/access', { params: buildParams(true) })
    items.value = response.data.items
    total.value = response.data.total
    stats.value = response.data.stats
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
    await downloadCsv('/access/export', buildParams(false), 'vpn-access.csv')
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function actionType(value: string): 'success' | 'danger' {
  return value === 'deny' ? 'danger' : 'success'
}

onMounted(() => {
  if (typeof route.query.username === 'string') {
    username.value = route.query.username
  }
  if (typeof route.query.dest === 'string') {
    destIp.value = route.query.dest
  }
  load()
})
</script>

<template>
  <div v-loading="loading">
    <div class="page-header">
      <div class="page-title">访问审计</div>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      title="只记录经过 VPN 隧道的连接元数据（目标 IP、上下行字节、时间），不采集内容；字节数为审计级近似值，不用于计费。"
      style="margin-bottom: 16px"
    />

    <el-row :gutter="16" class="stat-grid">
      <el-col :span="5">
        <el-card>
          <div class="muted">记录数</div>
          <h2>{{ stats?.records ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">用户数</div>
          <h2>{{ stats?.users ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">目标数</div>
          <h2>{{ stats?.targets ?? 0 }}</h2>
        </el-card>
      </el-col>
      <el-col :span="5">
        <el-card>
          <div class="muted">上行</div>
          <h2>{{ formatBytes(stats?.bytes_up ?? 0) }}</h2>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card>
          <div class="muted">下行</div>
          <h2>{{ formatBytes(stats?.bytes_down ?? 0) }}</h2>
        </el-card>
      </el-col>
    </el-row>

    <div class="toolbar">
      <el-select v-model="range" style="width: 130px" @change="search">
        <el-option label="今天" value="today" />
        <el-option label="24 小时" value="24h" />
        <el-option label="7 天" value="7d" />
        <el-option label="30 天" value="30d" />
        <el-option label="90 天" value="90d" />
        <el-option label="180 天" value="180d" />
        <el-option label="自定义" value="custom" />
        <el-option label="全部" value="all" />
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
        placeholder="用户名"
        clearable
        style="width: 150px"
        @keyup.enter="search"
      />
      <el-input
        v-model="destIp"
        placeholder="目标 IP"
        clearable
        style="width: 150px"
        @keyup.enter="search"
      />
      <el-input
        v-model="destCidr"
        placeholder="目标网段（反查）"
        clearable
        style="width: 190px"
        @keyup.enter="search"
      />
      <el-select
        v-model="action"
        placeholder="结果"
        clearable
        style="width: 110px"
        @change="search"
      >
        <el-option label="允许" value="allow" />
        <el-option label="拒绝" value="deny" />
      </el-select>
      <el-button type="primary" @click="search">查询</el-button>
      <el-button @click="exportCsv">导出 CSV</el-button>
    </div>

    <el-card>
      <el-table :data="items" stripe>
        <el-table-column prop="username" label="用户" min-width="120" />
        <el-table-column prop="virtual_ip" label="隧道 IP" width="130" />
        <el-table-column prop="dest_ip" label="目标 IP" width="140" />
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
        <el-table-column label="会话" min-width="140">
          <template #default="{ row }">
            <span class="muted">{{ row.session_id.slice(0, 12) }}</span>
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
  </div>
</template>