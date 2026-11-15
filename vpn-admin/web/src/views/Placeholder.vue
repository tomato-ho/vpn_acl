<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()
const title = (route.meta.title as string) || '功能'
</script>

<template>
  <div>
    <div class="page-header">
      <div class="page-title">{{ title }}</div>
    </div>
    <el-card>
      <el-empty :description="`${title} 将在后续里程碑提供`" />
    </el-card>
  </div>
</template>