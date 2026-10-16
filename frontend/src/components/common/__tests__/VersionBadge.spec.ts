import { mount, flushPromises } from '@vue/test-utils'
import { beforeEach, expect, it, vi } from 'vitest'
import VersionBadge from '../VersionBadge.vue'
import { performUpdate } from '@/api/admin/system'

const app = vi.hoisted(() => ({
  buildType: 'zcode', currentVersion: '0.2.17-zcode.2', latestVersion: '0.2.17-zcode.3',
  hasUpdate: true, versionLoading: false, releaseInfo: null, fetchVersion: vi.fn(), clearVersionCache: vi.fn()
}))
vi.mock('@/stores', () => ({ useAuthStore: () => ({ isAdmin: true }), useAppStore: () => app }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/composables/useClipboard', () => ({ useClipboard: () => ({ copied: false, copyToClipboard: vi.fn() }) }))
vi.mock('@/api/admin/system', () => ({ performUpdate: vi.fn(), restartService: vi.fn(), getRollbackVersions: vi.fn(), rollback: vi.fn() }))

beforeEach(() => {
  app.buildType = 'zcode'
  vi.clearAllMocks()
  vi.mocked(performUpdate).mockResolvedValue({ message: 'Updated', need_restart: true })
})

it('offers the web update and restart flow for the compatible fork', async () => {
  const wrapper = mount(VersionBadge)
  await wrapper.find('button').trigger('click')
  const update = wrapper.findAll('button').find(button => button.text().includes('version.updateNow'))
  expect(update).toBeDefined()
  await update!.trigger('click')
  await flushPromises()
  expect(performUpdate).toHaveBeenCalledOnce()
  expect(wrapper.text()).toContain('version.restartNow')
  wrapper.unmount()
})

it('keeps source builds on the manual update flow', async () => {
  app.buildType = 'source'
  const wrapper = mount(VersionBadge)
  await wrapper.find('button').trigger('click')
  expect(wrapper.findAll('button').some(button => button.text().includes('version.updateNow'))).toBe(false)
  wrapper.unmount()
})
