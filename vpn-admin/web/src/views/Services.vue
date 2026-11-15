<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { GroupRow, ServiceRow, UserRow } from '../types'

const items = ref<ServiceRow[]>([])
const groups = ref<GroupRow[]>([])
const users = ref<UserRow[]>([])
const loading = ref(false)
const showForm = ref(false)
const saving = ref(false)
const showEdit = ref(false)
const editForm = reactive({
  id: 0,
  service: '',
  enabled: true,
})

const form = reactive({
  scope_type: 'global',
  scope_id: '',
  service: '',
  enabled: true,
})

const scopeOptions = computed(() => {
  if (form.scope_type === 'group') {
    return groups.value.map((group) => group.name)
  }
  if (form.scope_type === 'user') {
    return users.value.map((user) => user.username)
  }
  return []
})

async function loadServices() {
  loading.value = true
  try {
    const response = await api.get<{ items: ServiceRow[] }>('/services')
    items.value = response.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

async function loadOptions() {
  try {
    const [groupResponse, userResponse] = await Promise.all([
      api.get<{ items: GroupRow[] }>('/groups'),
      api.get<{ items: UserRow[] }>('/users', {
        params: { page: 1, page_size: 200 },
      }),
    ])
    groups.value = groupResponse.data.items
    users.value = userResponse.data.items
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

function openCreate() {
  form.scope_type = 'global'
  form.scope_id = ''
  form.service = ''
  form.enabled = true
  showForm.value = true
}

function onScopeTypeChange() {
  form.scope_id = ''
}

async function submit() {
  if (!form.service) {
    ElMessage.warning('请输入服务，例如 10.8.0.1:22/tcp')
    return
  }
  if (form.scope_type !== 'global' && !form.scope_id) {
    ElMessage.warning('请选择组或用户')
    return
  }
  saving.value = true
  try {
    await api.post('/services', {
      scope_type: form.scope_type,
      scope_id: form.scope_type === 'global' ? '' : form.scope_id,
      service: form.service,
      enabled: form.enabled,
    })
    ElMessage.success('服务已添加')
    showForm.value = false
    await loadServices()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    saving.value = false
  }
}

function openEdit(row: unknown) {
  const service = row as ServiceRow
  editForm.id = service.id
  editForm.service = service.service
  editForm.enabled = service.enabled
  showEdit.value = true
}

async function submitEdit() {
  if (!editForm.service) {
    ElMessage.warning('请输入服务')
    return
  }
  try {
    await api.patch(`/services/${editForm.id}`, {
      service: editForm.service,
      enabled: editForm.enabled,
    })
    ElMessage.success('服务已更新')
    showEdit.value = false
    await loadServices()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

async function toggleService(row: unknown, value: unknown) {
  const service = row as ServiceRow
  try {
    await api.patch(`/services/${service.id}`, {
      enabled: Boolean(value),
    })
    await loadServices()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
    await loadServices()
  }
}

async function removeService(row: unknown) {
  const service = row as ServiceRow
  try {
    await ElMessageBox.confirm(
      `确定删除服务 ${service.service}？`,
      '删除服务',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.delete(`/services/${service.id}`)
    ElMessage.success('服务已删除')
    await loadServices()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

onMounted(async () => {
  await Promise.all([loadServices(), loadOptions()])
})
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">服务管理</div>
      <div>
        <el-button type="primary" @click="openCreate">添加服务</el-button>
        <el-button @click="loadServices">刷新</el-button>
      </div>
    </div>

    <el-alert
      title="服务用于放行 VPN 客户端访问服务器本机服务，例如 10.8.0.1:22/tcp。服务变更会立即刷新在线会话的 nft 规则。"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    />

    <el-card>
      <el-table v-loading="loading" :data="items" stripe>
        <el-table-column prop="scope_type" label="范围" width="110" />
        <el-table-column prop="scope_id" label="范围对象" min-width="140" />
        <el-table-column prop="service" label="服务" min-width="220" />
        <el-table-column label="启用" width="90">
          <template #default="{ row }">
            <el-switch
              :model-value="row.enabled"
              @change="toggleService(row, $event)"
            />
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="180" />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" @click="removeService(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showForm" title="添加服务" width="480px">
      <el-form label-width="100px">
        <el-form-item label="范围">
          <el-select v-model="form.scope_type" style="width: 100%" @change="onScopeTypeChange">
            <el-option label="global" value="global" />
            <el-option label="group" value="group" />
            <el-option label="user" value="user" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.scope_type !== 'global'" label="范围对象">
          <el-select v-model="form.scope_id" filterable style="width: 100%">
            <el-option
              v-for="option in scopeOptions"
              :key="option"
              :label="option"
              :value="option"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="服务">
          <el-input v-model="form.service" placeholder="例如 10.8.0.1:22/tcp" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showForm = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="submit">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showEdit" title="编辑服务" width="480px">
      <el-form label-width="100px">
        <el-form-item label="服务">
          <el-input v-model="editForm.service" placeholder="例如 10.8.0.1:22/tcp" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="editForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEdit = false">取消</el-button>
        <el-button type="primary" @click="submitEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>