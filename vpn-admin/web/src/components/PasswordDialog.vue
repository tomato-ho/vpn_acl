<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'

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

const form = reactive({
  password: '',
  confirm: '',
})
const loading = ref(false)

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      form.password = ''
      form.confirm = ''
    }
  },
)

async function submit() {
  if (form.password.length < 8) {
    ElMessage.warning('密码至少 8 位')
    return
  }
  if (form.password !== form.confirm) {
    ElMessage.warning('两次密码不一致')
    return
  }
  loading.value = true
  try {
    await api.post(`/users/${encodeURI(props.username)}/password`, {
      password: form.password,
    })
    ElMessage.success('密码已重置')
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
    :title="`重置密码：${username}`"
    width="440px"
    :close-on-click-modal="false"
  >
    <el-form label-width="100px">
      <el-form-item label="新密码">
        <el-input v-model="form.password" type="password" show-password />
      </el-form-item>
      <el-form-item label="确认密码">
        <el-input v-model="form.confirm" type="password" show-password />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="submit">确认</el-button>
    </template>
  </el-dialog>
</template>