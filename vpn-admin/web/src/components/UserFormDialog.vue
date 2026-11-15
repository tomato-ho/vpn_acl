<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { GroupRow, UserRow } from '../types'

const props = defineProps<{
  modelValue: boolean
  mode: 'create' | 'edit'
  user?: UserRow
  groups: GroupRow[]
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: []
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value),
})

const form = reactive({
  username: '',
  display_name: '',
  group: '',
  fixed_ip: '',
  password: '',
  confirm: '',
  enabled: true,
  must_change_password: true,
})

const loading = ref(false)

function reset() {
  form.username = props.mode === 'edit' ? props.user?.username ?? '' : ''
  form.display_name = props.mode === 'edit' ? props.user?.display_name ?? '' : ''
  form.group = props.mode === 'edit' ? props.user?.group ?? '' : ''
  form.fixed_ip = props.mode === 'edit' ? props.user?.fixed_ip ?? '' : ''
  form.password = ''
  form.confirm = ''
  form.enabled = props.mode === 'edit' ? props.user?.enabled ?? true : true
  form.must_change_password =
    props.mode === 'edit' ? props.user?.must_change_password ?? false : true
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      reset()
    }
  },
)

async function submit() {
  if (!form.username || !form.group || !form.fixed_ip) {
    ElMessage.warning('用户名、组和固定 IP 必填')
    return
  }
  if (props.mode === 'create') {
    if (form.password.length < 8) {
      ElMessage.warning('密码至少 8 位')
      return
    }
    if (form.password !== form.confirm) {
      ElMessage.warning('两次密码不一致')
      return
    }
  }

  loading.value = true
  try {
    if (props.mode === 'create') {
      await api.post('/users', {
        username: form.username,
        display_name: form.display_name,
        group: form.group,
        fixed_ip: form.fixed_ip,
        password: form.password,
        must_change_password: form.must_change_password,
      })
      ElMessage.success('用户已创建')
    } else {
      await api.patch(`/users/${encodeURI(form.username)}`, {
        display_name: form.display_name,
        group: form.group,
        fixed_ip: form.fixed_ip,
        enabled: form.enabled,
        must_change_password: form.must_change_password,
      })
      ElMessage.success('用户已更新')
    }
    emit('saved')
    visible.value = false
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <el-dialog
    v-model="visible"
    :title="mode === 'create' ? '新建用户' : '编辑用户'"
    width="520px"
    :close-on-click-modal="false"
  >
    <el-form label-width="110px">
      <el-form-item label="用户名">
        <el-input v-model="form.username" :disabled="mode === 'edit'" />
      </el-form-item>
      <el-form-item label="显示名">
        <el-input v-model="form.display_name" />
      </el-form-item>
      <el-form-item label="组">
        <el-select v-model="form.group" style="width: 100%">
          <el-option
            v-for="group in groups"
            :key="group.id"
            :label="`${group.name} (${group.ip_start}-${group.ip_end})`"
            :value="group.name"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="固定 IP">
        <el-input v-model="form.fixed_ip" placeholder="例如 10.8.0.50" />
      </el-form-item>
      <template v-if="mode === 'create'">
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="form.confirm" type="password" show-password />
        </el-form-item>
      </template>
      <el-form-item v-if="mode === 'edit'" label="启用">
        <el-switch v-model="form.enabled" />
      </el-form-item>
      <el-form-item label="强制改密">
        <el-switch v-model="form.must_change_password" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>