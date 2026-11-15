<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { GroupRow } from '../types'

const props = defineProps<{
  modelValue: boolean
  mode: 'create' | 'edit'
  group?: GroupRow
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
  name: '',
  ip_start: '',
  ip_end: '',
  description: '',
})
const loading = ref(false)

watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    form.name = props.mode === 'edit' ? props.group?.name ?? '' : ''
    form.ip_start = props.mode === 'edit' ? props.group?.ip_start ?? '' : ''
    form.ip_end = props.mode === 'edit' ? props.group?.ip_end ?? '' : ''
    form.description =
      props.mode === 'edit' ? props.group?.description ?? '' : ''
  },
)

async function submit() {
  if (!form.name || !form.ip_start || !form.ip_end) {
    ElMessage.warning('组名、IP 起始和结束地址必填')
    return
  }
  loading.value = true
  try {
    if (props.mode === 'create') {
      await api.post('/groups', {
        name: form.name,
        ip_start: form.ip_start,
        ip_end: form.ip_end,
        description: form.description,
      })
      ElMessage.success('组已创建')
    } else if (props.group) {
      await api.patch(`/groups/${props.group.id}`, {
        name: form.name,
        ip_start: form.ip_start,
        ip_end: form.ip_end,
        description: form.description,
      })
      ElMessage.success('组已更新')
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
    :title="mode === 'create' ? '新建组' : '编辑组'"
    width="480px"
    :close-on-click-modal="false"
  >
    <el-form label-width="100px">
      <el-form-item label="组名">
        <el-input v-model="form.name" />
      </el-form-item>
      <el-form-item label="IP 起始">
        <el-input v-model="form.ip_start" placeholder="例如 10.8.0.30" />
      </el-form-item>
      <el-form-item label="IP 结束">
        <el-input v-model="form.ip_end" placeholder="例如 10.8.0.99" />
      </el-form-item>
      <el-form-item label="描述">
        <el-input v-model="form.description" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>