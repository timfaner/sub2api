<template>
  <details class="space-y-3 rounded border border-gray-200 p-3 dark:border-dark-600">
    <summary class="cursor-pointer font-medium">{{ t('admin.accounts.zcode.webTitle') }}</summary>
    <p v-if="bound" role="status">{{ t('admin.accounts.zcode.webBound') }}</p>
    <p class="input-hint">{{ t('admin.accounts.zcode.webScope') }}</p>
    <p class="input-hint">{{ t('admin.accounts.zcode.webInstructions') }}</p>
    <a href="https://chat.z.ai/api/v1/auths/" target="_blank" rel="noopener noreferrer" class="text-primary-600 underline">{{ t('admin.accounts.zcode.webOpen') }}</a>
    <label class="block">
      <span>{{ t('admin.accounts.zcode.webToken') }}</span>
      <input v-model="token" type="password" autocomplete="off" spellcheck="false" class="input mt-1" :disabled="busy" />
    </label>
    <label class="flex items-start gap-2">
      <input v-model="consent" type="checkbox" :disabled="busy" />
      <span class="text-sm">{{ t('admin.accounts.zcode.webConsent') }}</span>
    </label>
    <p v-if="failed" role="alert" class="text-sm text-red-600">{{ t('admin.accounts.zcode.webError') }}</p>
    <button type="button" class="btn btn-secondary" :disabled="busy || !consent || !token.trim()" @click="bind">{{ t('admin.accounts.zcode.webBind') }}</button>
  </details>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { bindZCodeWebSession } from '@/api/admin/zcode'
const props = defineProps<{ accountId: number; bound: boolean }>()
const emit = defineEmits<{ bound: [] }>()
const { t } = useI18n()
const token = ref('')
const consent = ref(false)
const busy = ref(false)
const failed = ref(false)
let disposed = false
async function bind() {
  if (busy.value || !consent.value || !token.value.trim() || disposed) return
  busy.value = true
  failed.value = false
  try {
    await bindZCodeWebSession(props.accountId, token.value.trim())
    if (!disposed) emit('bound')
  } catch { if (!disposed) failed.value = true }
  finally { token.value = ''; consent.value = false; busy.value = false }
}
onBeforeUnmount(() => { disposed = true; token.value = ''; consent.value = false })
</script>
