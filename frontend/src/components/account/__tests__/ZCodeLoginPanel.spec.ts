import { mount, flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ZCodeLoginPanel from '../ZCodeLoginPanel.vue'
import { startZCodeLogin, pollZCodeLogin } from '@/api/admin/zcode'
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/api/admin/zcode', () => ({ startZCodeLogin: vi.fn(), pollZCodeLogin: vi.fn(), cancelZCodeLogin: vi.fn() }))
beforeEach(() => {
  vi.useFakeTimers()
  vi.mocked(startZCodeLogin).mockResolvedValue({ flow_id: 'flow', status: 'pending', authorize_url: 'https://chat.z.ai/authorize', poll_interval_sec: 3 })
  vi.mocked(pollZCodeLogin).mockResolvedValue({ flow_id: 'flow', status: 'ready' })
})
afterEach(() => { vi.useRealTimers(); vi.resetAllMocks() })
describe('ZCodeLoginPanel', () => {
  it('polls server-owned authorization and emits completion once', async () => {
    const w = mount(ZCodeLoginPanel, { props: { accountId: 42 } })
    await w.find('button').trigger('click')
    await flushPromises()
    expect(w.find('a').attributes('href')).toBe('https://chat.z.ai/authorize')
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(pollZCodeLogin).toHaveBeenCalledWith(42, 'flow')
    expect(w.emitted('ready')).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(30000)
    expect(pollZCodeLogin).toHaveBeenCalledTimes(1)
    w.unmount()
  })
  it('ignores a late start response after closing', async () => {
    let finish!: (value: Awaited<ReturnType<typeof startZCodeLogin>>) => void
    vi.mocked(startZCodeLogin).mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const w = mount(ZCodeLoginPanel, { props: { accountId: 42 } })
    await w.find('button').trigger('click')
    w.unmount()
    finish({ flow_id: 'flow', status: 'pending', poll_interval_sec: 1 })
    await flushPromises()
    await vi.advanceTimersByTimeAsync(10000)
    expect(pollZCodeLogin).not.toHaveBeenCalled()
  })
  it('resumes the same flow after a transient poll failure', async () => {
    vi.mocked(pollZCodeLogin).mockRejectedValueOnce(new Error('network'))
    const w = mount(ZCodeLoginPanel, { props: { accountId: 42 } })
    await w.find('button').trigger('click')
    await flushPromises()
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(w.find('[role="alert"]').exists()).toBe(true)
    await w.findAll('button').find(b => b.text().endsWith('.resume'))!.trigger('click')
    await flushPromises()
    expect(startZCodeLogin).toHaveBeenCalledTimes(1)
    expect(w.emitted('ready')).toHaveLength(1)
    w.unmount()
  })
})

it('shows saved authorization and sanitized root rejection separately from login progress', () => {
  const w = mount(ZCodeLoginPanel, { props: { accountId: 42, credentials: {
    expires_at: '2026-10-17T00:00:00Z', zcode_retry_reason: 'root_authorization_rejected',
    zcode_retry_after: '2026-10-17T00:05:00Z'
  } } })
  expect(w.text()).toContain('admin.accounts.zcode.saved')
  expect(w.text()).toContain('admin.accounts.zcode.rootRejected')
  expect(w.text()).toContain('admin.accounts.zcode.retryAt')
  expect(w.find('button').text()).toBe('admin.accounts.zcode.reauthorize')
  w.unmount()
})
