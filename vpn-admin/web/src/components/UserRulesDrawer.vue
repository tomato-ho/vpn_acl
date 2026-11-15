<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { UserDetail, UserRule } from '../types'

const props = defineProps<{
  modelValue: boolean
  username: string
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: []
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value),
})

const detail = ref<UserDetail | null>(null)
const loading = ref(false)
const addForm = reactive({
  rule_type: 'allow',
  cidr: '',
  enabled: true,
})

async function loadDetail() {
  if (!props.username) {
    return
  }
  loading.value = true
  try {
    const response = await api.get<UserDetail>(
      `/users/${encodeURI(props.username)}`,
    )
    detail.value = response.data
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
      addForm.cidr = ''
      addForm.rule_type = 'allow'
      addForm.enabled = true
      loadDetail()
    }
  },
)

async function addRule() {
  if (!addForm.cidr) {
    ElMessage.warning('请输入 CIDR')
    return
  }
  try {
    await api.post(`/users/${encodeURI(props.username)}/rules`, {
      rule_type: addForm.rule_type,
      cidr: addForm.cidr,
      enabled: addForm.enabled,
    })
    addForm.cidr = ''
    ElMessage.success('规则已添加')
    emit('saved')
    await loadDetail()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}

async function setEnabled(row: unknown, value: unknown) {
  const rule = row as UserRule
  const enabled = Boolean(value)
  try {
    await api.patch(
      `/users/${encodeURI(props.username)}/rules/${rule.id}`,
      { enabled },
    )
    emit('saved')
    await loadDetail()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
    await loadDetail()
  }
}

async function removeRule(row: unknown) {
  const rule = row as UserRule
  try {
    await ElMessageBox.confirm(`确定删除 ${rule.rule_type} ${rule.cidr}？`, '确认', {
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    await api.delete(
      `/users/${encodeURI(props.username)}/rules/${rule.id}`,
    )
    ElMessage.success('规则已删除')
    emit('saved')
    await loadDetail()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  }
}
</script>

<template>
  <el-drawer v-model="visible" :title="`规则管理：${username}`" size="55%">
    <div v-loading="loading">
      <el-form inline>
        <el-form-item label="类型">
          <el-select v-model="addForm.rule_type" style="width: 110px">
            <el-option label="allow" value="allow" />
            <el-option label="deny" value="deny" />
          </el-select>
        </el-form-item>
        <el-form-item label="CIDR">
          <el-input
            v-model="addForm.cidr"
            placeholder="例如 192.168.100.102/32"
            style="width: 260px"
          />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="addForm.enabled" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="addRule">添加规则</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="detail?.rules ?? []" stripe>
        <el-table-column label="类型" width="100">
          <template #default="{ row }">
            <el-tag :type="row.rule_type === 'allow' ? 'success' : 'danger'">
              {{ row.rule_type }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="cidr" label="CIDR" min-width="220" />
        <el-table-column label="启用" width="90">
          <template #default="{ row }">
            <el-switch
              :model-value="row.enabled"
              @change="setEnabled(row, $event)"
            />
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="180" />
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button link type="danger" @click="removeRule(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-divider content-position="left">有效策略</el-divider>
      <template v-if="detail">
        <el-alert
          v-if="detail.policy_error"
          :title="detail.policy_error"
          type="warning"
          :closable="false"
          show-icon
        />
        <template v-else-if="detail.policy">
          <div class="policy-row">
            <span class="muted">固定 IP：</span>
            <el-tag>{{ detail.policy.fixed_ip }}</el-tag>
          </div>
          <div class="policy-row">
            <span class="muted">allow：</span>
            <el-tag
              v-for="item in detail.policy.allow"
              :key="`allow-${item}`"
              type="success"
            >
              {{ item }}
            </el-tag>
            <span v-if="detail.policy.allow.length === 0" class="muted">无</span>
          </div>
          <div class="policy-row">
            <span class="muted">deny：</span>
            <el-tag
              v-for="item in detail.policy.deny"
              :key="`deny-${item}`"
              type="danger"
            >
              {{ item }}
            </el-tag>
            <span v-if="detail.policy.deny.length === 0" class="muted">无</span>
          </div>
          <div class="policy-row">
            <span class="muted">下发路由：</span>
            <el-tag
              v-for="item in detail.policy.push_routes"
              :key="`route-${item}`"
              type="warning"
            >
              {{ item }}
            </el-tag>
            <span v-if="detail.policy.push_routes.length === 0" class="muted">无</span>
          </div>
          <div class="policy-row">
            <span class="muted">服务：</span>
            <el-tag
              v-for="item in detail.policy.services"
              :key="`service-${item}`"
              type="info"
            >
              {{ item }}
            </el-tag>
            <span v-if="detail.policy.services.length === 0" class="muted">无</span>
          </div>
        </template>
      </template>
    </div>
  </el-drawer>
</template>

<style scoped>
.policy-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
</style>