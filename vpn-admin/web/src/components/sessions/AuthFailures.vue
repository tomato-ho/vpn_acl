<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../../api/client'
import { downloadCsv } from '../../api/csv'
import { apiErrorMessage } from '../../api/errors'
import type { AuthFailure } from '../../types'

const range = ref('today')
const customRange = ref<[string, string] | null>(null)
const username = ref('')
const includeDeleted = ref(true)
const page = ref(1)
const pageSize = ref(50)
const loading = ref(false)
const items = ref<AuthFailure[]>([])
const total = ref(0)

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
    const response = await api.get<{
      items: AuthFailure[]
      total: number
      page: number
      page_size: number
    }>('/auth-failures', { params: buildParams(true) })
    items.value = response.data.items
    total.value = response.data.total
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
      '/auth-failures/export',
      buildParams(false),
      'vpn-auth-failures.csv',
    )
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

onMounted(load)
</script>

<template>
  <div v-loading="loading">
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
        <el-table-column prop="auth_time" label="时间" min-width="180" />
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column label="用户状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.user_exists ? 'success' : 'info'">
              {{ row.user_exists ? '当前' : '已删除' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="reply" label="结果" min-width="140" />
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