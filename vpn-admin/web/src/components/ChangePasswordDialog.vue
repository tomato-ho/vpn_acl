<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import { useAuthStore, type Me } from '../stores/auth'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const visible = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit('update:modelValue', value),
})

const auth = useAuthStore()
const form = reactive({
  current_password: '',
  new_password: '',
  confirm: '',
})
const loading = ref(false)

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      form.current_password = ''
      form.new_password = ''
      form.confirm = ''
    }
  },
)

async function submit() {
  if (!form.current_password || form.new_password.length < 8) {
    ElMessage.warning('新密码至少 8 位')
    return
  }
  if (form.new_password !== form.confirm) {
    ElMessage.warning('两次新密码不一致')
    return
  }
  loading.value = true
  try {
    const response = await api.post<Me>('/me/password', {
      current_password: form.current_password,
      new_password: form.new_password,
    })
    auth.setMe(response.data)
    ElMessage.success('密码已修改')
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
    title="修改管理员密码"
    width="440px"
    :close-on-click-modal="false"
  >
    <el-form label-width="100px">
      <el-form-item label="当前密码">
        <el-input v-model="form.current_password" type="password" show-password />
      </el-form-item>
      <el-form-item label="新密码">
        <el-input v-model="form.new_password" type="password" show-password />
      </el-form-item>
      <el-form-item label="确认密码">
        <el-input v-model="form.confirm" type="password" show-password />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>