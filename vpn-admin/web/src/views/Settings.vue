<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'
import { apiErrorMessage } from '../api/errors'
import type { SettingsValues } from '../types'

const form = reactive<SettingsValues>({
  allowed_target_networks: '',
  allowed_service_ips: '',
  tunnel_network: '',
  max_rules_per_user: '128',
  max_services_per_user: '16',
})
const loading = ref(false)
const saving = ref(false)

async function load() {
  loading.value = true
  try {
    const response = await api.get<Partial<SettingsValues>>('/settings')
    form.allowed_target_networks =
      response.data.allowed_target_networks ?? ''
    form.allowed_service_ips = response.data.allowed_service_ips ?? ''
    form.tunnel_network = response.data.tunnel_network ?? ''
    form.max_rules_per_user = response.data.max_rules_per_user ?? '128'
    form.max_services_per_user = response.data.max_services_per_user ?? '16'
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    await api.patch('/settings', {
      allowed_target_networks: form.allowed_target_networks,
      allowed_service_ips: form.allowed_service_ips,
      tunnel_network: form.tunnel_network,
      max_rules_per_user: form.max_rules_per_user,
      max_services_per_user: form.max_services_per_user,
    })
    ElMessage.success('设置已保存')
    await load()
  } catch (error) {
    ElMessage.error(apiErrorMessage(error))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div v-loading="loading">
    <div class="page-header">
      <div class="page-title">设置</div>
      <div>
        <el-button @click="load">重新加载</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </div>
    </div>

    <el-alert
      title="设置修改会立即刷新在线会话的 nft 规则；固定 IP/组 IP 范围类变更需下次连接生效。保存前会校验现有用户、组、规则和服务。"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    />

    <el-card>
      <el-form label-width="180px">
        <el-form-item label="允许的目标网段">
          <el-input
            v-model="form.allowed_target_networks"
            type="textarea"
            :rows="3"
            placeholder="例如 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
          />
        </el-form-item>
        <el-form-item label="允许的服务 IP">
          <el-input
            v-model="form.allowed_service_ips"
            placeholder="例如 10.8.0.1,192.168.100.109"
          />
        </el-form-item>
        <el-form-item label="隧道网段">
          <el-input v-model="form.tunnel_network" placeholder="例如 10.8.0.0/24" />
        </el-form-item>
        <el-form-item label="每用户最大规则数">
          <el-input v-model="form.max_rules_per_user" />
        </el-form-item>
        <el-form-item label="每用户最大服务数">
          <el-input v-model="form.max_services_per_user" />
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>