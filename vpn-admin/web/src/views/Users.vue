<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { GroupRow, UserRow } from '../types'
import UserFormDialog from '../components/UserFormDialog.vue'
import PasswordDialog from '../components/PasswordDialog.vue'
import UserRulesDrawer from '../components/UserRulesDrawer.vue'

const items = ref<UserRow[]>([])
const groups = ref<GroupRow[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(50)
const query = ref('')
const group = ref('')
const loading = ref(false)

const showForm = ref(false)
const formMode = ref<'create' | 'edit'>('create')
const editingUser = ref<UserRow | undefined>(undefined)

const showPassword = ref(false)
const passwordUser = ref('')

const showRules = ref(false)
const rulesUser = ref('')
const router = useRouter()

function openAccess(row: unknown) {
  const user = row as UserRow
  router.push({ path: '/access', query: { username: user.username } })
}

async function load() {
  loading.value = true
  try {
    const response = await api.get<{
      items: UserRow[]
      total: number
      page: number
      page_size: number
    }>('/users', {
      params: {
        query: query.value,
        group: group.value,
        page: page.value,
        page_size: pageSize.value,
      },
    })
    items.value = response.data.items
    total.value = response.data.total
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

async function loadGroups() {
  try {
    const response = await api.get<{ items: GroupRow[] }>('/groups')
    groups.value = response.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
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

function openCreate() {
  editingUser.value = undefined
  formMode.value = 'create'
  showForm.value = true
}

function openEdit(row: unknown) {
  editingUser.value = row as UserRow
  formMode.value = 'edit'
  showForm.value = true
}

function openPassword(row: unknown) {
  passwordUser.value = (row as UserRow).username
  showPassword.value = true
}

function openRules(row: unknown) {
  rulesUser.value = (row as UserRow).username
  showRules.value = true
}

async function removeUser(row: unknown) {
  const user = row as UserRow
  try {
    await ElMessageBox.confirm(
      `确定删除用户 ${user.username}？该操作会清理其认证、规则和用户服务。`,
      '删除用户',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.delete(`/users/${encodeURI(user.username)}`)
    ElMessage.success('用户已删除')
    await load()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function onSaved() {
  load()
}

onMounted(async () => {
  await Promise.all([load(), loadGroups()])
})
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">用户管理</div>
      <div>
        <el-button type="primary" @click="openCreate">新建用户</el-button>
        <el-button @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert
      title="用户规则变更会立即刷新在线会话；禁用、改组、改固定 IP 会让用户下线重连。"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    />

    <div class="toolbar">
      <el-input
        v-model="query"
        placeholder="搜索用户名或显示名"
        clearable
        style="width: 260px"
        @keyup.enter="search"
      />
      <el-input
        v-model="group"
        placeholder="按组过滤"
        clearable
        style="width: 180px"
        @keyup.enter="search"
      />
      <el-button type="primary" @click="search">查询</el-button>
    </div>

    <el-card>
      <el-table v-loading="loading" :data="items" stripe>
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column prop="display_name" label="显示名" min-width="140" />
        <el-table-column prop="group" label="组" min-width="120" />
        <el-table-column prop="fixed_ip" label="固定 IP" width="140" />
        <el-table-column label="启用" width="90">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">
              {{ row.enabled ? '是' : '否' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="需改密" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.must_change_password" type="warning">是</el-tag>
            <span v-else class="muted">否</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="180" />
        <el-table-column label="操作" width="330" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link type="primary" @click="openPassword(row)">密码</el-button>
            <el-button link type="primary" @click="openRules(row)">规则</el-button>
            <el-button link type="primary" @click="openAccess(row)">访问记录</el-button>
            <el-button link type="danger" @click="removeUser(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :page-sizes="[20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next"
          @current-change="changePage"
          @size-change="changePageSize"
        />
      </div>
    </el-card>

    <UserFormDialog
      v-model="showForm"
      :mode="formMode"
      :user="editingUser"
      :groups="groups"
      @saved="onSaved"
    />
    <PasswordDialog
      v-model="showPassword"
      :username="passwordUser"
      @saved="onSaved"
    />
    <UserRulesDrawer
      v-model="showRules"
      :username="rulesUser"
      @saved="onSaved"
    />
  </div>
</template>