<template>
  <section class="space-y-3 rounded-lg border border-gray-200 p-4 dark:border-dark-600">
    <h3 class="font-medium">{{ t('admin.accounts.zcode.title') }}</h3>
    <p class="input-hint">{{ t(hasAuthorization ? 'admin.accounts.zcode.saved' : 'admin.accounts.zcode.pending') }}</p>
    <div v-if="retryReason" role="status" class="rounded bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">
      <p>{{ t(retryReason === 'root_authorization_rejected' ? 'admin.accounts.zcode.rootRejected' : 'admin.accounts.zcode.retrying') }}</p>
      <p v-if="retryAt">{{ t('admin.accounts.zcode.retryAt', { time: retryAt }) }}</p>
    </div>
    <p v-if="error" role="alert" class="text-sm text-red-600">{{ t('admin.accounts.zcode.error') }}</p>
    <p v-if="ready" role="status">{{ t('admin.accounts.zcode.ready') }}</p>
    <template v-else>
      <a v-if="authorizeURL" :href="authorizeURL" target="_blank" rel="noopener noreferrer" class="btn btn-primary">
        {{ t('admin.accounts.zcode.open') }}
      </a>
      <p v-if="flow && !error" role="status" class="text-sm">{{ t('admin.accounts.zcode.waiting') }}</p>
      <div class="flex gap-3">
        <button v-if="!flow" type="button" class="btn btn-primary" :disabled="busy" @click="start">
          {{ t(hasAuthorization ? 'admin.accounts.zcode.reauthorize' : 'admin.accounts.zcode.start') }}
        </button>
        <button v-if="flow && error" type="button" class="btn btn-primary" :disabled="busy" @click="poll">
          {{ t('admin.accounts.zcode.resume') }}
        </button>
        <button v-if="flow" type="button" class="btn btn-secondary" :disabled="busy" @click="cancel">
          {{ t('admin.accounts.zcode.cancel') }}
        </button>
      </div>
    </template>
    <ZCodeWebSessionPanel v-if="hasAuthorization && !flow && !busy" :account-id="accountId" :bound="credentials?.zcode_web_session_bound === true" @bound="emit('ready')" />
  </section>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { startZCodeLogin, pollZCodeLogin, cancelZCodeLogin } from '@/api/admin/zcode'
import ZCodeWebSessionPanel from './ZCodeWebSessionPanel.vue'
const props = defineProps<{ accountId: number; credentials?: Record<string, unknown> }>()
const emit = defineEmits<{ ready: [] }>()
const { t } = useI18n()
const hasAuthorization = computed(() => props.credentials?.zcode_pending !== true && typeof props.credentials?.expires_at === 'string')
const retryReason = computed(() => {
  const reason = props.credentials?.zcode_retry_reason
  return reason === 'root_authorization_rejected' || reason === 'upstream_temporarily_unavailable' ? reason : ''
})
const retryAt = computed(() => {
  const value = props.credentials?.zcode_retry_after
  if (typeof value !== 'string') return ''
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : ''
})
const flow = ref('')
const authorizeURL = ref('')
const busy = ref(false)
const error = ref(false)
const ready = ref(false)
let interval = 5
let timer: ReturnType<typeof setTimeout> | undefined
let disposed = false
const stop = () => { clearTimeout(timer); timer = undefined }
const schedule = () => { stop(); if (!disposed) timer = setTimeout(poll, interval * 1000) }
async function start() {
  if (busy.value || disposed) return
  busy.value = true
  error.value = false
  try {
    const result = await startZCodeLogin(props.accountId)
    if (disposed) return
    flow.value = result.flow_id
    authorizeURL.value = result.authorize_url || ''
    interval = Math.max(1, result.poll_interval_sec || 5)
    schedule()
  } catch { if (!disposed) error.value = true }
  finally { busy.value = false }
}
async function poll() {
  stop()
  if (busy.value || disposed || !flow.value) return
  busy.value = true
  error.value = false
  try {
    const result = await pollZCodeLogin(props.accountId, flow.value)
    if (disposed) return
    if (result.status === 'ready') {
      ready.value = true
      flow.value = ''
      authorizeURL.value = ''
      emit('ready')
    } else {
      interval = Math.max(1, result.poll_interval_sec || interval)
      schedule()
    }
  } catch { if (!disposed) error.value = true }
  finally { busy.value = false }
}
async function cancel() {
  stop()
  if (busy.value || disposed || !flow.value) return
  busy.value = true
  try {
    await cancelZCodeLogin(props.accountId, flow.value)
    flow.value = ''
    authorizeURL.value = ''
    error.value = false
  } catch { if (!disposed) error.value = true }
  finally { busy.value = false }
}
onBeforeUnmount(() => { disposed = true; stop() })
</script>
