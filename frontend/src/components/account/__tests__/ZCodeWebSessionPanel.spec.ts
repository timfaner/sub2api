import { mount, flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ZCodeWebSessionPanel from '../ZCodeWebSessionPanel.vue'
import { bindZCodeWebSession } from '@/api/admin/zcode'
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/api/admin/zcode', () => ({ bindZCodeWebSession: vi.fn() }))
afterEach(() => vi.resetAllMocks())
describe('web session binding', () => {
  it('requires explicit consent and clears sensitive input after success', async () => {
    vi.mocked(bindZCodeWebSession).mockResolvedValue()
    const w = mount(ZCodeWebSessionPanel, { props: { accountId: 7, bound: false } })
    await w.find('input[type=password]').setValue('private-token')
    expect(w.find('button').attributes('disabled')).toBeDefined()
    await w.find('input[type=checkbox]').setValue(true)
    await w.find('button').trigger('click')
    await flushPromises()
    expect(bindZCodeWebSession).toHaveBeenCalledWith(7, 'private-token')
    expect(w.emitted('bound')).toHaveLength(1)
    expect((w.find('input[type=password]').element as HTMLInputElement).value).toBe('')
    expect((w.find('input[type=checkbox]').element as HTMLInputElement).checked).toBe(false)
    w.unmount()
  })
  it('clears failed credentials and does not render server error text', async () => {
    vi.mocked(bindZCodeWebSession).mockRejectedValue(new Error('private-token'))
    const w = mount(ZCodeWebSessionPanel, { props: { accountId: 7, bound: true } })
    await w.find('input[type=password]').setValue('private-token')
    await w.find('input[type=checkbox]').setValue(true)
    await w.find('button').trigger('click')
    await flushPromises()
    expect(w.emitted('bound')).toBeUndefined()
    expect(w.text()).not.toContain('private-token')
    expect(w.find('[role=alert]').exists()).toBe(true)
    expect((w.find('input[type=password]').element as HTMLInputElement).value).toBe('')
    w.unmount()
  })
})

it('clears the draft and ignores late success when the selected account changes', async () => {
  let finish!: () => void
  vi.mocked(bindZCodeWebSession).mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const w = mount(ZCodeWebSessionPanel, { props: { accountId: 7, bound: false } })
  await w.find('input[type=password]').setValue('private-token')
  await w.find('input[type=checkbox]').setValue(true)
  await w.find('button').trigger('click')
  await w.setProps({ accountId: 8 })
  expect((w.find('input[type=password]').element as HTMLInputElement).value).toBe('')
  expect((w.find('input[type=checkbox]').element as HTMLInputElement).checked).toBe(false)
  finish()
  await flushPromises()
  expect(w.emitted('bound')).toBeUndefined()
  w.unmount()
})
