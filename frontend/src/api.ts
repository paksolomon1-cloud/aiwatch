import type {
  AgentEvent,
  Alert,
  DemoSeedResponse,
  EventIngestResponse,
  HealthResponse,
  SessionReplay,
  ToolFingerprint,
  ToolObservation,
} from './types'

const BACKEND_URL = 'http://127.0.0.1:7330'

export const BACKEND_OFFLINE_MESSAGE =
  'Backend offline or blocked. Start the backend with: py -3.12 -m uvicorn app.main:app --reload --port 7330. Demo controls require AIWATCH_DEV_MODE=true.'

export class AiWatchApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'AiWatchApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    const response = await fetch(`${BACKEND_URL}${path}`, {
      headers: {
        Accept: 'application/json',
        ...(init?.headers ?? {}),
      },
      ...init,
    })

    if (!response.ok) {
      throw new AiWatchApiError(`AIWatch request failed with status ${response.status}`, response.status)
    }

    return (await response.json()) as T
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(BACKEND_OFFLINE_MESSAGE)
    }

    if (error instanceof Error) {
      throw error
    }

    throw new Error('Unknown AIWatch client error')
  }
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/v1/health')
}

export function getEvents(): Promise<AgentEvent[]> {
  return request<AgentEvent[]>('/v1/events')
}

export function getAlerts(): Promise<Alert[]> {
  return request<Alert[]>('/v1/alerts')
}

export function getTools(): Promise<ToolFingerprint[]> {
  return request<ToolFingerprint[]>('/v1/tools')
}

export function getTool(fingerprintId: string): Promise<ToolFingerprint> {
  return request<ToolFingerprint>(`/v1/tools/${encodeURIComponent(fingerprintId)}`)
}

export function getToolHistory(fingerprintId: string): Promise<ToolObservation[]> {
  return request<ToolObservation[]>(`/v1/tools/${encodeURIComponent(fingerprintId)}/history`)
}

export function getSessionReplay(sessionId: string): Promise<SessionReplay> {
  return request<SessionReplay>(`/v1/sessions/${encodeURIComponent(sessionId)}/replay`)
}

export function clearDevData(): Promise<{ status: string; message: string }> {
  return request<{ status: string; message: string }>('/v1/dev/clear', {
    method: 'DELETE',
  })
}

export function seedDemo(clear = true, extended = false): Promise<DemoSeedResponse> {
  return request<DemoSeedResponse>(
    `/v1/dev/seed-demo?clear=${clear ? 'true' : 'false'}&extended=${extended ? 'true' : 'false'}`,
    {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: '{}',
    },
  )
}

export function postEvent(event: Record<string, unknown>): Promise<EventIngestResponse> {
  return request<EventIngestResponse>('/v1/events', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(event),
  })
}
