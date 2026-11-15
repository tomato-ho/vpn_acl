<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { GroupRow } from '../types'
import GroupFormDialog from '../components/GroupFormDialog.vue'
import GroupRulesDrawer from '../components/GroupRulesDrawer.vue'

const items = ref<GroupRow[]>([])
const loading = ref(false)

const showForm = ref(false)
const formMode = ref<'create' | 'edit'>('create')
const editingGroup = ref<GroupRow | undefined>(undefined)

const showRules = ref(false)
const rulesGroupId = ref(0)
const rulesGroupName = ref('')

async function load() {
  loading.value = true
  try {
    const response = await api.get<{ items: GroupRow[] }>('/groups')
    items.value = response.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editingGroup.value = undefined
  formMode.value = 'create'
  showForm.value = true
}

function openEdit(row: unknown) {
  editingGroup.value = row as GroupRow
  formMode.value = 'edit'
  showForm.value = true
}

function openRules(row: unknown) {
  const group = row as GroupRow
  rulesGroupId.value = group.id
  rulesGroupName.value = group.name
  showRules.value = true
}

async function removeGroup(row: unknown) {
  const group = row as GroupRow
  try {
    await ElMessageBox.confirm(
      `确定删除组 ${group.name}？组规则和组级服务会一起清理。`,
      '删除组',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.delete(`/groups/${group.id}`)
    ElMessage.success('组已删除')
    await load()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">组管理</div>
      <div>
        <el-button type="primary" @click="openCreate">新建组</el-button>
        <el-button @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert
      title="组规则和组修改会立即刷新在线会话；组 IP 范围变更不会改变已建立隧道地址，下次连接生效。修改范围时组内用户固定 IP 必须仍在新范围内。"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    />

    <el-card>
      <el-table v-loading="loading" :data="items" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="组名" min-width="140" />
        <el-table-column label="IP 范围" min-width="220">
          <template #default="{ row }">
            {{ row.ip_start }} - {{ row.ip_end }}
          </template>
        </el-table-column>
        <el-table-column prop="user_count" label="用户数" width="100" />
        <el-table-column prop="rule_count" label="规则数" width="100" />
        <el-table-column prop="description" label="描述" min-width="200" />
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link type="primary" @click="openRules(row)">规则</el-button>
            <el-button link type="danger" @click="removeGroup(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <GroupFormDialog
      v-model="showForm"
      :mode="formMode"
      :group="editingGroup"
      @saved="load"
    />
    <GroupRulesDrawer
      v-model="showRules"
      :group-id="rulesGroupId"
      :group-name="rulesGroupName"
      @saved="load"
    />
  </div>
</template>