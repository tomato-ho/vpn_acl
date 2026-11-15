<script setup lang="ts">
import { ref } from 'vue'
import OnlineSessions from '../components/sessions/OnlineSessions.vue'
import HistorySessions from '../components/sessions/HistorySessions.vue'
import AuthFailures from '../components/sessions/AuthFailures.vue'

const activeTab = ref('online')
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">会话</div>
    </div>

    <el-tabs v-model="activeTab" type="border-card">
      <el-tab-pane label="在线会话" name="online">
        <OnlineSessions />
      </el-tab-pane>
      <el-tab-pane label="历史会话" name="history" lazy>
        <HistorySessions />
      </el-tab-pane>
      <el-tab-pane label="认证失败" name="failures" lazy>
        <AuthFailures />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>