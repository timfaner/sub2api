import { apiClient } from '../client'

export interface ZCodeLoginView {
  flow_id: string
  status: 'pending' | 'ready'
  authorize_url?: string
  expires_at?: number
  poll_interval_sec?: number
}
const path = (id: number) => `/admin/accounts/${id}/zcode/login`
export async function startZCodeLogin(id: number): Promise<ZCodeLoginView> {
  return (await apiClient.post<ZCodeLoginView>(path(id), {}, { timeout: 50_000 })).data
}
export async function pollZCodeLogin(id: number, flow: string): Promise<ZCodeLoginView> {
  return (await apiClient.post<ZCodeLoginView>(`${path(id)}/${encodeURIComponent(flow)}/poll`, {}, { timeout: 50_000 })).data
}
export async function cancelZCodeLogin(id: number, flow: string): Promise<void> {
  await apiClient.delete(`${path(id)}/${encodeURIComponent(flow)}`)
}
export async function bindZCodeWebSession(id: number, token: string): Promise<void> {
  await apiClient.post(`/admin/accounts/${id}/zcode/web-session`, { token, consent: true }, { timeout: 50_000 })
}
