<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'

interface AuditRow {
  id: number
  operator: string
  action: string
  target: string
  before: string
  after: string
  created_at: string
}

const items = ref<AuditRow[]>([])
const page = ref(1)
const pageSize = 50
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const response = await api.get<{ items: AuditRow[] }>('/audit', {
      params: {
        limit: pageSize,
        offset: (page.value - 1) * pageSize,
      },
    })
    items.value = response.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

function changePage(value: number) {
  page.value = value
  load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">审计日志</div>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-card>
      <el-table v-loading="loading" :data="items" stripe>
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="audit-detail">
              <div>before:</div>
              <pre>{{ row.before || '-' }}</pre>
              <div>after:</div>
              <pre>{{ row.after || '-' }}</pre>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="id" label="ID" width="90" />
        <el-table-column prop="created_at" label="时间" min-width="180" />
        <el-table-column prop="operator" label="操作人" width="140" />
        <el-table-column prop="action" label="动作" min-width="140" />
        <el-table-column prop="target" label="目标" min-width="180" />
      </el-table>
      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          layout="prev, pager, next"
          @current-change="changePage"
        />
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.audit-detail {
  padding: 8px 24px;
}

.audit-detail pre {
  background: #f5f7fa;
  padding: 8px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>