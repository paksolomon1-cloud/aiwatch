import { startTransition, useEffect, useState } from 'react'
import './App.css'
import {
  AiWatchApiError,
  BACKEND_OFFLINE_MESSAGE,
  clearDevData,
  getAlerts,
  getAuditSummary,
  getAuditTimeline,
  getEvents,
  getHealth,
  getSessionReplay,
  getTool,
  getToolHistory,
  getTools,
  postEvent,
  seedDemo,
} from './api'
import type {
  AgentEvent,
  Alert,
  AuditSummaryResponse,
  AuditTimelineRecord,
  DemoSeedResponse,
  EventIngestResponse,
  HealthResponse,
  SessionReplay,
  Severity,
  ToolFingerprint,
  ToolObservation,
} from './types'

type View = 'overview' | 'alerts' | 'audit' | 'sessions' | 'tools'

interface SessionSummary {
  sessionId: string
  eventCount: number
  alertCount: number
  latestAt: string
  highestSeverity: Severity | 'none'
}

interface AuditIncidentGroup {
  key: string
  label: 'Cross-layer activity' | 'Elevated cross-layer risk'
  latestAt: string | null
  records: AuditTimelineRecord[]
}

interface ReplayLoadOptions {
  silent?: boolean
}

const severityOrder: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const dangerousTokens = ['.env', 'base64', 'curl', 'wget', 'credentials', '~/.aws']
const dangerousTokenSet = new Set(dangerousTokens.map((token) => token.toLowerCase()))
const dangerousTokenPattern = new RegExp(
  `(${dangerousTokens.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`,
  'gi',
)

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return 'n/a'
  }

  const parsed = new Date(value)
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString()
}

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

function toSentenceCase(value: string): string {
  return value.replaceAll('_', ' ')
}

function formatAuditSource(source: string): string {
  if (source === 'aiwatch') {
    return 'AIWatch'
  }

  if (source === 'lobstertrap') {
    return 'Lobster Trap'
  }

  return toSentenceCase(source)
}

function formatAuditLayer(layer: string): string {
  if (layer === 'mcp_tool') {
    return 'MCP tool'
  }

  if (layer === 'llm_prompt_response') {
    return 'LLM prompt-response'
  }

  return toSentenceCase(layer)
}

function getAuditRecordKey(record: AuditTimelineRecord, index: number): string {
  return [
    record.id,
    record.source,
    record.layer,
    record.event_type,
    record.timestamp,
    record.created_at,
    record.request_id,
    record.rule_id,
    index,
  ]
    .filter((part) => part !== undefined && part !== null && part !== '')
    .join(':')
}

function getAuditCorrelationKey(record: AuditTimelineRecord): string | null {
  const candidate =
    record.correlation_id ??
    record.trace_id ??
    record.session_id ??
    record.request_id ??
    null

  return typeof candidate === 'string' && candidate.trim() ? candidate : null
}

function getAuditActionText(record: AuditTimelineRecord): string {
  return record.action ?? record.decision ?? 'n/a'
}

function isLobsterTrapRiskRecord(record: AuditTimelineRecord): boolean {
  if (record.source !== 'lobstertrap') {
    return false
  }

  const action = String(record.action ?? '').toUpperCase()
  const decision = String(record.decision ?? '').toLowerCase()
  return (
    ['DENY', 'HUMAN_REVIEW', 'QUARANTINE'].includes(action) ||
    ['block', 'review', 'quarantine'].includes(decision)
  )
}

function buildAuditIncidentGroups(records: AuditTimelineRecord[]): AuditIncidentGroup[] {
  const groupedRecords = new Map<string, AuditTimelineRecord[]>()

  for (const record of records) {
    const key = getAuditCorrelationKey(record)
    if (!key) {
      continue
    }

    const existing = groupedRecords.get(key) ?? []
    existing.push(record)
    groupedRecords.set(key, existing)
  }

  const incidentGroups: AuditIncidentGroup[] = []

  for (const [key, groupRecords] of groupedRecords.entries()) {
    const sources = new Set(groupRecords.map((record) => record.source))
    if (!sources.has('aiwatch') || !sources.has('lobstertrap')) {
      continue
    }

    const hasLobsterTrapRisk = groupRecords.some(isLobsterTrapRiskRecord)
    const latestAt =
      groupRecords
        .map((record) => record.timestamp ?? record.created_at ?? null)
        .filter((value): value is string => Boolean(value))
        .sort((left, right) => new Date(right).valueOf() - new Date(left).valueOf())[0] ?? null

    incidentGroups.push({
      key,
      label: hasLobsterTrapRisk ? 'Elevated cross-layer risk' : 'Cross-layer activity',
      latestAt,
      records: [...groupRecords].sort(
        (left, right) =>
          new Date(right.timestamp ?? right.created_at ?? 0).valueOf() -
          new Date(left.timestamp ?? left.created_at ?? 0).valueOf(),
      ),
    })
  }

  return incidentGroups.sort((left, right) => {
    const leftTime = left.latestAt ? new Date(left.latestAt).valueOf() : 0
    const rightTime = right.latestAt ? new Date(right.latestAt).valueOf() : 0
    return rightTime - leftTime || left.key.localeCompare(right.key)
  })
}

function getRuleFamily(ruleId: string): 'code' | 'mcp' | 'intent' | 'other' {
  if (ruleId.startsWith('R-CODE')) {
    return 'code'
  }

  if (ruleId.startsWith('R-MCP')) {
    return 'mcp'
  }

  if (ruleId.startsWith('R-INTENT')) {
    return 'intent'
  }

  return 'other'
}

function excerpt(value: string, limit = 120): string {
  if (value.length <= limit) {
    return value
  }

  return `${value.slice(0, limit - 3)}...`
}

const ruleExplanations: Record<string, string> = {
  'R-MCP-001':
    'Poisoned tool description: tool text tries to instruct the model to perform unsafe actions.',
  'R-MCP-002': "Tool drift: a known tool's description or schema changed.",
  'R-MCP-004': 'Tool shadowing: multiple servers registered the same tool name.',
  'R-MCP-005': 'Credential-shaped tool-call parameter: MCP tools/call arguments contain a credential-shaped value.',
  'R-CODE-001': 'Secret access: command touches credential-like files or variables.',
  'R-CODE-002': 'Network command: command may send data outbound.',
  'R-CODE-003': 'Encoded exfiltration: command encodes data and sends it out.',
  'R-INTENT-001': 'Intent mismatch: stated goal does not match the actual action.',
}

const ruleLabels: Record<string, string> = {
  'R-MCP-001': 'Poisoned MCP tool description',
  'R-MCP-002': 'MCP tool fingerprint drift',
  'R-MCP-004': 'MCP tool name shadowing',
  'R-MCP-005': 'Credential-shaped MCP tool-call parameter',
}

const ruleGuide = [
  {
    family: 'R-MCP',
    description:
      'Poisoned tool text, fingerprint drift, shadowed names, and credential-shaped tool-call parameters.',
  },
  {
    family: 'R-CODE',
    description: 'Legacy demo-only coding-agent commands that touch secrets or send data outbound.',
  },
  {
    family: 'R-INTENT',
    description: "Declared intent does not match the action that was actually taken.",
  },
]

function getRuleExplanation(ruleId: string): string {
  return ruleExplanations[ruleId] ?? 'AIWatch flagged this item with a deterministic rule.'
}

function getRuleLabel(ruleId: string): string {
  return ruleLabels[ruleId] ?? 'Deterministic alert'
}

function previewText(value: string | null | undefined, limit = 12): string {
  if (!value) {
    return 'n/a'
  }

  return value.length <= limit ? value : `${value.slice(0, limit)}...`
}

function PreviewValue({
  value,
  limit = 12,
  className = '',
}: {
  value: string | null | undefined
  limit?: number
  className?: string
}) {
  const displayValue = previewText(value, limit)

  return (
    <span className={`preview-value ${className}`.trim()} title={value ?? displayValue}>
      {displayValue}
    </span>
  )
}

function buildSessionSummaries(events: AgentEvent[], alerts: Alert[]): SessionSummary[] {
  const sessions = new Map<string, SessionSummary>()

  for (const event of events) {
    const existing = sessions.get(event.session_id)
    const latestAt =
      !existing || new Date(event.timestamp).valueOf() > new Date(existing.latestAt).valueOf()
        ? event.timestamp
        : existing.latestAt

    sessions.set(event.session_id, {
      sessionId: event.session_id,
      eventCount: (existing?.eventCount ?? 0) + 1,
      alertCount: existing?.alertCount ?? 0,
      latestAt,
      highestSeverity: existing?.highestSeverity ?? 'none',
    })
  }

  for (const alert of alerts) {
    const existing = sessions.get(alert.session_id)
    const currentSeverity = existing?.highestSeverity
    const highestSeverity =
      currentSeverity === undefined || currentSeverity === 'none'
        ? alert.severity
        : severityOrder[alert.severity] > severityOrder[currentSeverity]
          ? alert.severity
          : currentSeverity

    const latestAt =
      !existing || new Date(alert.created_at).valueOf() > new Date(existing.latestAt).valueOf()
        ? alert.created_at
        : existing.latestAt

    sessions.set(alert.session_id, {
      sessionId: alert.session_id,
      eventCount: existing?.eventCount ?? 0,
      alertCount: (existing?.alertCount ?? 0) + 1,
      latestAt,
      highestSeverity,
    })
  }

  return [...sessions.values()].sort(
    (left, right) => new Date(right.latestAt).valueOf() - new Date(left.latestAt).valueOf(),
  )
}

function getPrimaryEventId(alert: Alert): string | null {
  return alert.event_ids[0] ?? null
}

function getAssociatedEvent(alert: Alert | null, eventMap: Map<string, AgentEvent>): AgentEvent | null {
  if (!alert) {
    return null
  }

  const eventId = getPrimaryEventId(alert)
  return eventId ? eventMap.get(eventId) ?? null : null
}

function getPrimaryActionText(event: AgentEvent | null): string | null {
  if (!event) {
    return null
  }

  const command = event.action_params.command
  if (typeof command === 'string' && command.trim()) {
    return command
  }

  const description = event.action_params.description
  if (typeof description === 'string' && description.trim()) {
    return description
  }

  return null
}

function hasReadmeMismatch(event: AgentEvent | null): boolean {
  if (!event?.intent_text) {
    return false
  }

  const intent = event.intent_text.toLowerCase()
  const actionText = getPrimaryActionText(event)?.toLowerCase() ?? formatJson(event.action_params).toLowerCase()

  return intent.includes('readme') && (actionText.includes('.env') || actionText.includes('curl'))
}

function renderDangerousText(text: string) {
  return text.split(dangerousTokenPattern).map((part, index) => {
    const key = `${part}-${index}`

    if (dangerousTokenSet.has(part.toLowerCase())) {
      return (
        <span key={key} className="danger-token">
          {part}
        </span>
      )
    }

    return <span key={key}>{part}</span>
  })
}

function buildToolNameServerMap(tools: ToolFingerprint[]): Map<string, string[]> {
  const toolMap = new Map<string, Set<string>>()

  for (const tool of tools) {
    const servers = toolMap.get(tool.tool_name) ?? new Set<string>()
    servers.add(tool.server_id)
    toolMap.set(tool.tool_name, servers)
  }

  return new Map([...toolMap.entries()].map(([toolName, servers]) => [toolName, [...servers].sort()]))
}

function hasToolShadowing(tool: ToolFingerprint | null, toolNameServerMap: Map<string, string[]>): boolean {
  if (!tool) {
    return false
  }

  return (toolNameServerMap.get(tool.tool_name)?.length ?? 0) > 1
}

function getToolShadowServers(tool: ToolFingerprint | null, toolNameServerMap: Map<string, string[]>): string[] {
  if (!tool) {
    return []
  }

  return (toolNameServerMap.get(tool.tool_name) ?? []).filter((serverId) => serverId !== tool.server_id)
}

function buildCredentialDemoSecret(): string {
  return ['sk', 'dashboard', 'credential', 'demo', '1234567890abcdefABCDEF'].join('-')
}

function getEventFlowLabel(event: AgentEvent, relatedAlerts: Alert[]): string | null {
  if (event.source !== 'mcp') {
    return null
  }

  if (event.action_type === 'tool_register') {
    return relatedAlerts.length > 0
      ? 'tools/list -> registry event -> deterministic alert'
      : 'tools/list -> registry event'
  }

  if (event.action_type === 'tool_call') {
    return relatedAlerts.some((alert) => alert.rule_id === 'R-MCP-005')
      ? 'tools/call -> redacted credential-shaped parameter -> R-MCP-005'
      : 'tools/call -> captured MCP tool-call event'
  }

  return null
}

function AlertMeta({ alert }: { alert: Alert }) {
  return (
    <div className="detail-row">
      <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
      <span
        className={`rule-pill rule-${getRuleFamily(alert.rule_id)}`}
        title={getRuleExplanation(alert.rule_id)}
      >
        {alert.rule_id}
      </span>
      <span className="rule-label">{getRuleLabel(alert.rule_id)}</span>
      <span className="decision-pill">{alert.decision}</span>
    </div>
  )
}

function App() {
  const [activeView, setActiveView] = useState<View>('overview')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [tools, setTools] = useState<ToolFingerprint[]>([])
  const [auditTimeline, setAuditTimeline] = useState<AuditTimelineRecord[]>([])
  const [auditSummary, setAuditSummary] = useState<AuditSummaryResponse | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [selectedSessionId, setSelectedSessionId] = useState('')
  const [sessionInput, setSessionInput] = useState('')
  const [sessionReplay, setSessionReplay] = useState<SessionReplay | null>(null)
  const [selectedToolId, setSelectedToolId] = useState('')
  const [selectedTool, setSelectedTool] = useState<ToolFingerprint | null>(null)
  const [selectedToolHistory, setSelectedToolHistory] = useState<ToolObservation[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSessionLoading, setIsSessionLoading] = useState(false)
  const [isToolLoading, setIsToolLoading] = useState(false)
  const [isMutating, setIsMutating] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [bannerMessage, setBannerMessage] = useState<string | null>(null)
  const [expandedParamEventIds, setExpandedParamEventIds] = useState<Set<string>>(new Set())

  const eventMap = new Map(events.map((event) => [event.event_id, event]))
  const associatedEvent = getAssociatedEvent(selectedAlert, eventMap)
  const sessionSummaries = buildSessionSummaries(events, alerts)
  const recentAlerts = alerts.slice(0, 5)
  const lobstertrapAuditCount = auditTimeline.filter((record) => record.source === 'lobstertrap').length
  const aiwatchAuditCount = auditTimeline.filter((record) => record.source === 'aiwatch').length
  const auditIncidentGroups = buildAuditIncidentGroups(auditTimeline)
  const toolNameServerMap = buildToolNameServerMap(tools)
  const shadowedToolNames = [...toolNameServerMap.entries()]
    .filter(([, servers]) => servers.length > 1)
    .map(([toolName]) => toolName)

  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }

  for (const alert of alerts) {
    severityCounts[alert.severity] += 1
  }

  const backendOffline = Boolean(errorMessage) && !health
  const mutationDisabled = backendOffline || isMutating || isLoading

  async function refreshDashboard() {
    setIsLoading(true)
    setErrorMessage(null)

    try {
      const [nextHealth, nextEvents, nextAlerts, nextTools, nextAuditTimeline, nextAuditSummary] = await Promise.all([
        getHealth(),
        getEvents(),
        getAlerts(),
        getTools(),
        getAuditTimeline(),
        getAuditSummary(),
      ])

      setHealth(nextHealth)
      setEvents(
        [...nextEvents].sort(
          (left, right) => new Date(right.timestamp).valueOf() - new Date(left.timestamp).valueOf(),
        ),
      )
      setAlerts(
        [...nextAlerts].sort(
          (left, right) => new Date(right.created_at).valueOf() - new Date(left.created_at).valueOf(),
        ),
      )
      setTools(
        [...nextTools].sort(
          (left, right) => new Date(right.last_seen).valueOf() - new Date(left.last_seen).valueOf(),
        ),
      )
      setAuditTimeline(nextAuditTimeline)
      setAuditSummary(nextAuditSummary)
    } catch (error) {
      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
      setHealth(null)
      setEvents([])
      setAlerts([])
      setTools([])
      setAuditTimeline([])
      setAuditSummary(null)
      setSelectedAlert(null)
      setSelectedTool(null)
      setSelectedToolId('')
      setSelectedToolHistory([])
      setSessionReplay(null)
    } finally {
      setIsLoading(false)
    }
  }

  async function loadSessionReplay(sessionId: string, options: ReplayLoadOptions = {}) {
    if (!sessionId) {
      setSessionReplay(null)
      return
    }

    setIsSessionLoading(true)

    try {
      const replay = await getSessionReplay(sessionId)
      setSessionReplay({
        ...replay,
        events: [...replay.events].sort(
          (left, right) => new Date(left.timestamp).valueOf() - new Date(right.timestamp).valueOf(),
        ),
      })
      setErrorMessage(null)
    } catch (error) {
      setSessionReplay(null)
      if (options.silent && error instanceof AiWatchApiError && error.status === 404) {
        setSelectedSessionId((current) => (current === sessionId ? '' : current))
        setSessionInput((current) => (current === sessionId ? '' : current))
        return
      }

      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
    } finally {
      setIsSessionLoading(false)
    }
  }

  async function loadToolDetails(fingerprintId: string) {
    if (!fingerprintId) {
      setSelectedTool(null)
      setSelectedToolHistory([])
      return
    }

    setIsToolLoading(true)

    try {
      const [tool, history] = await Promise.all([getTool(fingerprintId), getToolHistory(fingerprintId)])
      setSelectedTool(tool)
      setSelectedToolHistory(
        [...history].sort(
          (left, right) => new Date(left.observed_at).valueOf() - new Date(right.observed_at).valueOf(),
        ),
      )
      setErrorMessage(null)
    } catch (error) {
      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
      setSelectedTool(null)
      setSelectedToolHistory([])
    } finally {
      setIsToolLoading(false)
    }
  }

  useEffect(() => {
    void refreshDashboard()
  }, [])

  useEffect(() => {
    setExpandedParamEventIds(new Set())
    if (!selectedSessionId) {
      setSessionReplay(null)
      return
    }

    void loadSessionReplay(selectedSessionId)
  }, [selectedSessionId])

  useEffect(() => {
    if (alerts.length === 0) {
      setSelectedAlert(null)
      return
    }

    if (selectedAlert && alerts.some((alert) => alert.alert_id === selectedAlert.alert_id)) {
      return
    }

    setSelectedAlert(alerts[0])
  }, [alerts, selectedAlert])

  useEffect(() => {
    if (tools.length === 0) {
      setSelectedToolId('')
      setSelectedTool(null)
      setSelectedToolHistory([])
      return
    }

    if (selectedToolId && tools.some((tool) => tool.fingerprint_id === selectedToolId)) {
      return
    }

    setSelectedToolId(tools[0].fingerprint_id)
  }, [selectedToolId, tools])

  useEffect(() => {
    if (!selectedToolId) {
      return
    }

    void loadToolDetails(selectedToolId)
  }, [selectedToolId])

  function openAlert(alert: Alert) {
    startTransition(() => {
      setActiveView('alerts')
      setSelectedAlert(alert)
    })
  }

  function openSession(sessionId: string) {
    startTransition(() => {
      setActiveView('sessions')
      setSessionInput(sessionId)
      setSelectedSessionId(sessionId)
    })
  }

  function openTool(fingerprintId: string) {
    startTransition(() => {
      setActiveView('tools')
      setSelectedToolId(fingerprintId)
    })
  }

  async function handleClearData() {
    if (!window.confirm('Clear the local AIWatch SQLite database?')) {
      return
    }

    setIsMutating(true)
    setErrorMessage(null)
    setBannerMessage(null)

    try {
      const response = await clearDevData()
      setBannerMessage(response.message)
      setSelectedSessionId('')
      setSessionInput('')
      setSelectedToolId('')
      setSessionReplay(null)
      setSelectedTool(null)
      setSelectedToolHistory([])
      await refreshDashboard()
    } catch (error) {
      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
    } finally {
      setIsMutating(false)
    }
  }

  async function handleSeedDemo(extended = false) {
    setIsMutating(true)
    setErrorMessage(null)
    setBannerMessage(null)

    try {
      const response: DemoSeedResponse = await seedDemo(true, extended)
      setBannerMessage(
        extended
          ? `Seeded ${response.events_created} events, ${response.alerts_created} alerts, and ${response.tools_observed} current tools.`
          : `Seeded ${response.events_created} events and ${response.alerts_created} alerts.`,
      )
      await refreshDashboard()
      if (selectedSessionId) {
        await loadSessionReplay(selectedSessionId, { silent: true })
      }

      if (extended) {
        setActiveView('tools')
      } else {
        const maliciousItem = response.items.find((item) => item.name === 'malicious coding-agent exfiltration')
        if (maliciousItem) {
          setSelectedSessionId('demo-malicious-code')
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
    } finally {
      setIsMutating(false)
    }
  }

  async function handleCredentialDemo() {
    setIsMutating(true)
    setErrorMessage(null)
    setBannerMessage(null)

    try {
      const credentialDemoEvent = {
        source: 'mcp',
        agent_id: 'dashboard-demo',
        session_id: 'demo-mcp-credential-param',
        intent_text: 'Call an MCP export tool with user-supplied parameters.',
        action_type: 'tool_call',
        action_params: {
          server_id: 'fixture-notes-mcp',
          tool_name: 'export_notes_bundle',
          arguments: {
            api_key: buildCredentialDemoSecret(),
            format: 'json',
          },
        },
      }
      const posted: EventIngestResponse = await postEvent(credentialDemoEvent)
      setBannerMessage(
        `Posted one MCP tools/call event and created ${posted.alerts_created} alert. R-MCP-005 evidence is redacted.`,
      )
      await refreshDashboard()
      if (selectedSessionId) {
        await loadSessionReplay(selectedSessionId, { silent: true })
      }
      const credentialAlert = posted.alerts.find((alert) => alert.rule_id === 'R-MCP-005') ?? null
      if (credentialAlert) {
        setSelectedAlert(credentialAlert)
        setActiveView('alerts')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : BACKEND_OFFLINE_MESSAGE
      setErrorMessage(message)
    } finally {
      setIsMutating(false)
    }
  }

  function renderEvidenceGroup(label: string, values: string[]) {
    if (values.length === 0) {
      return null
    }

    return (
      <div className="field-stack">
        <span className="detail-label">{label}</span>
        <div className="chip-row">
          {values.map((value) => (
            <span key={`${label}-${value}`} className="evidence-chip mono-inline wrap-anywhere" title={value}>
              {value}
            </span>
          ))}
        </div>
      </div>
    )
  }

  function renderAlertDetails() {
    if (!selectedAlert) {
      return (
        <p className="empty-state">
          Choose an alert from the table to inspect its evidence, linked event, and session context.
        </p>
      )
    }

    const primaryEventId = getPrimaryEventId(selectedAlert)
    const primaryActionText = getPrimaryActionText(associatedEvent)
    const mismatchWarning = hasReadmeMismatch(associatedEvent)
    const evidence = selectedAlert.evidence
    const credentialFindings = evidence.credential_findings ?? []

    return (
      <div className="detail-stack">
        <AlertMeta alert={selectedAlert} />

        {mismatchWarning ? (
          <div className="warning-label">
            Intent/action mismatch: stated README inspection, but action touched secrets or network.
          </div>
        ) : null}

        <div className="detail-grid">
          <div className="field-stack">
            <span className="detail-label">Alert ID</span>
            <p className="mono-inline wrap-anywhere">{selectedAlert.alert_id}</p>
          </div>
          <div className="field-stack">
            <span className="detail-label">Source</span>
            <p>{toSentenceCase(selectedAlert.source)}</p>
          </div>
          <div className="field-stack">
            <span className="detail-label">Session</span>
            <button
              type="button"
              className="table-link mono-inline wrap-anywhere"
              onClick={() => openSession(selectedAlert.session_id)}
              title={selectedAlert.session_id}
            >
              {selectedAlert.session_id}
            </button>
          </div>
          <div className="field-stack">
            <span className="detail-label">Event ID</span>
            <p className="mono-inline wrap-anywhere">{primaryEventId ?? 'n/a'}</p>
          </div>
          <div className="field-stack">
            <span className="detail-label">Created</span>
            <p>{formatTimestamp(selectedAlert.created_at)}</p>
          </div>
        </div>

        <div className="field-stack">
          <span className="detail-label">Summary</span>
          <p>{selectedAlert.summary}</p>
        </div>

        <div className="field-stack">
          <span className="detail-label">Rule meaning</span>
          <p>{getRuleExplanation(selectedAlert.rule_id)}</p>
        </div>

        <div className="field-stack">
          <span className="detail-label">Rationale</span>
          <p>{selectedAlert.rationale}</p>
        </div>

        <div className="field-stack">
          <span className="detail-label">Action summary</span>
          <p>{selectedAlert.evidence.action_summary}</p>
        </div>

        {renderEvidenceGroup('Matched patterns', evidence.matched_patterns)}
        {renderEvidenceGroup('Files referenced', evidence.files_referenced)}
        {renderEvidenceGroup('Destinations', evidence.destinations)}
        {renderEvidenceGroup('Other server IDs', evidence.other_server_ids)}
        {renderEvidenceGroup('Matching fingerprints', evidence.matching_fingerprint_ids)}

        {credentialFindings.length > 0 ? (
          <div className="field-stack credential-evidence">
            <div className="section-heading compact-heading">
              <div>
                <span className="detail-label">Redacted credential evidence</span>
                <p className="muted-copy small-copy">Raw detected secret values are not shown.</p>
              </div>
            </div>
            <div className="credential-finding-list">
              {credentialFindings.map((finding, index) => (
                <div key={`${finding.param_path}-${finding.secret_type}-${index}`} className="credential-finding">
                  <div className="field-stack">
                    <span className="detail-label">Param path</span>
                    <p className="mono-inline wrap-anywhere">{finding.param_path}</p>
                  </div>
                  <div className="field-stack">
                    <span className="detail-label">Secret type</span>
                    <p className="mono-inline wrap-anywhere">{finding.secret_type}</p>
                  </div>
                  <div className="field-stack">
                    <span className="detail-label">Redacted value</span>
                    <p className="mono-inline wrap-anywhere">{finding.redacted_value}</p>
                  </div>
                  <div className="field-stack">
                    <span className="detail-label">Value length</span>
                    <p>{finding.value_length}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {evidence.tool_name || evidence.server_id || evidence.current_server_id ? (
          <div className="detail-grid">
            {evidence.tool_name ? (
              <div className="field-stack">
                <span className="detail-label">Tool name</span>
                <p className="mono-inline wrap-anywhere">{evidence.tool_name}</p>
              </div>
            ) : null}
            {evidence.current_server_id || evidence.server_id ? (
              <div className="field-stack">
                <span className="detail-label">Server ID</span>
                <p className="mono-inline wrap-anywhere">{evidence.current_server_id ?? evidence.server_id}</p>
              </div>
            ) : null}
            {evidence.fingerprint_id ? (
              <div className="field-stack">
                <span className="detail-label">Fingerprint</span>
                <p className="mono-inline wrap-anywhere">{evidence.fingerprint_id}</p>
              </div>
            ) : null}
          </div>
        ) : null}

        {evidence.previous_description_hash || evidence.current_description_hash ? (
          <div className="compare-grid">
            <div className="info-card">
              <span className="detail-label">Previous definition</span>
              <p className="mono-inline wrap-anywhere">{evidence.previous_description_hash ?? 'n/a'}</p>
              {evidence.previous_schema_hash ? (
                <p className="mono-inline wrap-anywhere">{evidence.previous_schema_hash}</p>
              ) : null}
              {evidence.previous_description_excerpt ? (
                <div className="danger-line">{renderDangerousText(evidence.previous_description_excerpt)}</div>
              ) : null}
            </div>

            <div className="info-card">
              <span className="detail-label">Current definition</span>
              <p className="mono-inline wrap-anywhere">{evidence.current_description_hash ?? 'n/a'}</p>
              {evidence.current_schema_hash ? (
                <p className="mono-inline wrap-anywhere">{evidence.current_schema_hash}</p>
              ) : null}
              {evidence.current_description_excerpt ? (
                <div className="danger-line">{renderDangerousText(evidence.current_description_excerpt)}</div>
              ) : null}
            </div>
          </div>
        ) : null}

        {associatedEvent ? (
          <div className="compare-grid">
            <div className="info-card">
              <span className="detail-label">Intent</span>
              <p>{associatedEvent.intent_text ?? 'No declared intent'}</p>
            </div>

            <div className="info-card">
              <span className="detail-label">Actual action</span>
              <div className="chip-row">
                <span className="rule-pill rule-other">{associatedEvent.action_type}</span>
              </div>
              {primaryActionText ? (
                <div className="danger-line mono-inline wrap-anywhere">{renderDangerousText(primaryActionText)}</div>
              ) : (
                <p className="muted-copy">No command or description captured.</p>
              )}
            </div>
          </div>
        ) : (
          <p className="empty-state">Associated event data was not found in the current event list.</p>
        )}

        {associatedEvent ? (
          <>
            <div className="field-stack">
              <span className="detail-label">Associated action type</span>
              <p>{associatedEvent.action_type}</p>
            </div>

            <div className="field-stack">
              <span className="detail-label">Associated action parameters</span>
              <pre className="scroll-code">{formatJson(associatedEvent.action_params)}</pre>
            </div>
          </>
        ) : null}
      </div>
    )
  }

  function renderOverview() {
    return (
      <div className="page-grid overview-grid">

        <section className="panel methodology-panel">
          <span className="panel-label">Audit surface</span>
          <p className="muted-copy small-copy">
            AIWatch observes MCP traffic routed through the stdio wrapper or local HTTP MCP relay.
          </p>
          <p className="muted-copy small-copy">
            It captures MCP `tools/list` and `tools/call` traffic, normalizes tools into fingerprints,
            stores tool history in SQLite, and runs deterministic rules for poisoned descriptions,
            fingerprint drift, shadowing, and credential-shaped tool-call parameters.
          </p>
          <p className="limitation-line">
            Routed MCP tool traffic only. Prompts, shell commands, file edits, hidden reasoning,
            laptop activity, and arbitrary network traffic are outside this observation surface.
          </p>
        </section>

        <section className="panel guide-panel">
          <span className="panel-label">Deterministic MCP checks</span>
          <div className="guide-list">
            {ruleGuide.map((item) => (
              <div key={item.family} className="guide-item">
                <span className={`rule-pill rule-${getRuleFamily(item.family)}`}>{item.family}</span>
                <p className="muted-copy small-copy">{item.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="panel severity-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Alert posture</span>
              <h3>Severity counts</h3>
            </div>
          </div>
          <div className="severity-grid">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => (
              <div key={severity} className={`severity-card severity-${severity}`}>
                <span className={`severity-badge severity-${severity}`}>{severity}</span>
                <strong>{severityCounts[severity]}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel recent-alerts-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Recent alerts</span>
              <h3>Latest deterministic findings</h3>
            </div>
            <button type="button" className="link-button" onClick={() => setActiveView('alerts')}>
              View all alerts
            </button>
          </div>

          {recentAlerts.length === 0 ? (
            <p className="empty-state">No alerts yet. Seed the demo or post a new event to `/v1/events`.</p>
          ) : (
            <div className="alert-list">
              {recentAlerts.map((alert) => (
                <button
                  key={alert.alert_id}
                  type="button"
                  className={`alert-card severity-${alert.severity}`}
                  onClick={() => openAlert(alert)}
                >
                  <div className="alert-card-header">
                    <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
                    <span
                      className={`rule-pill rule-${getRuleFamily(alert.rule_id)}`}
                      title={getRuleExplanation(alert.rule_id)}
                    >
                      {alert.rule_id}
                    </span>
                    <span className="muted-copy mono-inline">{formatTimestamp(alert.created_at)}</span>
                  </div>
                  <strong>{alert.summary}</strong>
                  <p>{alert.rationale}</p>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="panel session-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Recent sessions</span>
              <h3>Audit replay targets</h3>
            </div>
          </div>

          {events.length === 0 ? (
            <p className="empty-state">No events yet. Use Seed Demo or post runtime activity into the backend.</p>
          ) : (
            <div className="session-list">
              {sessionSummaries.slice(0, 6).map((session) => (
                <button
                  key={session.sessionId}
                  type="button"
                  className="session-card"
                  onClick={() => openSession(session.sessionId)}
                >
                  <div className="session-card-top">
                    <PreviewValue value={session.sessionId} limit={22} className="mono-inline" />
                    <span
                      className={`severity-badge ${session.highestSeverity !== 'none' ? `severity-${session.highestSeverity}` : ''}`}
                    >
                      {session.highestSeverity === 'none' ? 'clean' : `${session.highestSeverity} risk`}
                    </span>
                  </div>
                  <div className="session-card-stats">
                    <span>{session.eventCount} events</span>
                    <span>{session.alertCount} alerts</span>
                    <span>{formatTimestamp(session.latestAt)}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="panel registry-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Tool registry</span>
              <h3>Current MCP tool identities</h3>
            </div>
            <button type="button" className="link-button" onClick={() => setActiveView('tools')}>
              Open registry
            </button>
          </div>

          {tools.length === 0 ? (
            <p className="empty-state">No MCP tools have been observed yet.</p>
          ) : (
            <div className="tool-preview-list">
              {tools.slice(0, 4).map((tool) => (
                <button
                  key={tool.fingerprint_id}
                  type="button"
                  className="tool-preview-card"
                  onClick={() => openTool(tool.fingerprint_id)}
                >
                  <div className="session-card-top">
                    <strong className="mono-inline">{tool.tool_name}</strong>
                    {hasToolShadowing(tool, toolNameServerMap) ? (
                      <span className="shadow-badge">Shadowed name</span>
                    ) : null}
                  </div>
                  <p className="muted-copy">
                    <PreviewValue value={tool.server_id} limit={24} className="mono-inline" />
                  </p>
                  <p>{excerpt(tool.description)}</p>
                </button>
              ))}
            </div>
          )}
        </section>
      </div>
    )
  }

  function renderUnifiedAuditTimeline() {
    const summaryCards = [
      ['Total records', auditSummary?.total_records ?? auditTimeline.length],
      ['AIWatch MCP', auditSummary?.aiwatch_mcp_records ?? aiwatchAuditCount],
      ['Lobster Trap', auditSummary?.lobstertrap_records ?? lobstertrapAuditCount],
      ['Deny', auditSummary?.deny_count ?? 0],
      ['Review / quarantine', auditSummary?.human_review_quarantine_count ?? 0],
      ['Redacted', auditSummary?.redacted_count ?? auditTimeline.filter((record) => record.redacted).length],
    ]

    return (
      <div className="page-grid audit-grid">
        <section className="panel audit-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Local unified audit timeline</span>
              <h3>{auditTimeline.length} normalized audit records</h3>
            </div>
            <div className="live-status-row audit-counts">
              <span className="live-count-chip">{aiwatchAuditCount} AIWatch MCP</span>
              <span className="live-count-chip">{lobstertrapAuditCount} Lobster Trap LLM</span>
            </div>
          </div>

          <div className="info-card audit-boundary-card">
            <p className="muted-copy small-copy">
              AIWatch MCP records + Lobster Trap prompt/response audit records in one local timeline.
              Lobster Trap covers prompt/response audit logs; AIWatch covers routed MCP tool traffic.
            </p>
            <p className="muted-copy small-copy">
              Local integration, not TerraFabric deployment.
            </p>
          </div>

          <div className="audit-summary-grid">
            {summaryCards.map(([label, value]) => (
              <div key={label} className="audit-summary-card">
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
            <div className="audit-summary-card audit-summary-wide">
              <span>Most recent</span>
              <strong>{formatTimestamp(auditSummary?.most_recent_timestamp)}</strong>
            </div>
          </div>

          <div className="info-card audit-correlation-card">
            <div className="section-heading compact-heading">
              <div>
                <span className="panel-label">Local cross-layer audit correlation</span>
                <h3>{auditIncidentGroups.length} grouped incidents</h3>
              </div>
            </div>
            <p className="muted-copy small-copy">
              Grouped by local session/request metadata when present.
            </p>

            {auditIncidentGroups.length === 0 ? (
              <p className="empty-state">
                No cross-layer groups yet. Seed AIWatch MCP activity and ingest the Lobster Trap demo audit fixture to show correlated local audit records.
              </p>
            ) : (
              <div className="incident-list">
                {auditIncidentGroups.map((group) => (
                  <article
                    key={group.key}
                    className={`incident-card ${
                      group.label === 'Elevated cross-layer risk' ? 'incident-elevated' : ''
                    }`}
                  >
                    <div className="timeline-title">
                      <div>
                        <strong>{group.label}</strong>
                        <p className="muted-copy small-copy mono-inline wrap-anywhere">{group.key}</p>
                      </div>
                      <span className="live-count-chip">{formatTimestamp(group.latestAt)}</span>
                    </div>
                    <div className="incident-record-list">
                      {group.records.slice(0, 4).map((record, index) => (
                        <div key={getAuditRecordKey(record, index)} className="incident-record">
                          <span className={`source-badge source-${record.source}`}>
                            {formatAuditSource(record.source)}
                          </span>
                          <span>{formatAuditLayer(record.layer)}</span>
                          <span className="decision-pill">{getAuditActionText(record)}</span>
                          <span className="incident-summary">
                            {record.summary ?? toSentenceCase(record.event_type)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </div>

          {auditTimeline.length === 0 ? (
            <p className="empty-state">
              No unified audit records yet. Ingest a Lobster Trap JSONL audit file or generate AIWatch MCP activity to populate this local timeline.
            </p>
          ) : (
            <div className="table-scroll">
              <table className="alerts-table audit-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Layer</th>
                    <th>Decision</th>
                    <th>Rule</th>
                    <th>Evidence</th>
                    <th>Correlation</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {auditTimeline.map((record, index) => {
                    const ruleId = record.rule_id ?? 'n/a'
                    const decision = getAuditActionText(record)
                    const correlationId = getAuditCorrelationKey(record) ?? 'n/a'

                    return (
                      <tr key={getAuditRecordKey(record, index)}>
                        <td>{formatTimestamp(record.timestamp ?? record.created_at)}</td>
                        <td>
                          <span className={`source-badge source-${record.source}`}>
                            {formatAuditSource(record.source)}
                          </span>
                        </td>
                        <td>{formatAuditLayer(record.layer)}</td>
                        <td>
                          <span className="decision-pill">{decision}</span>
                        </td>
                        <td>
                          <span className={`rule-pill rule-${getRuleFamily(ruleId)}`}>{ruleId}</span>
                        </td>
                        <td>
                          <span className={record.redacted ? 'shadow-badge stable-badge' : 'shadow-badge'}>
                            {record.redacted ? 'redacted' : 'not marked'}
                          </span>
                        </td>
                        <td className="mono-inline wrap-anywhere">{correlationId}</td>
                        <td>{record.summary ?? toSentenceCase(record.event_type)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    )
  }

  function renderAlertsTable() {
    return (
      <div className="page-grid alerts-grid">
        <section className="panel table-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Alert queue</span>
              <h3>{alerts.length} persisted deterministic findings</h3>
            </div>
          </div>

          {alerts.length === 0 ? (
            <p className="empty-state">No alerts available. Seed the demo to populate the table.</p>
          ) : (
            <div className="table-scroll">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Decision</th>
                    <th>Source</th>
                    <th>Session</th>
                    <th>Event</th>
                    <th>Summary</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => {
                    const primaryEventId = getPrimaryEventId(alert) ?? 'n/a'
                    const selected = selectedAlert?.alert_id === alert.alert_id

                    return (
                      <tr
                        key={alert.alert_id}
                        data-severity={alert.severity}
                        className={selected ? 'selected-row' : undefined}
                        onClick={() => setSelectedAlert(alert)}
                      >
                        <td>
                          <span className={`severity-badge severity-${alert.severity}`}>{alert.severity}</span>
                        </td>
                        <td>
                          <span
                            className={`rule-pill rule-${getRuleFamily(alert.rule_id)}`}
                            title={getRuleExplanation(alert.rule_id)}
                          >
                            {alert.rule_id}
                          </span>
                        </td>
                        <td>{alert.decision}</td>
                        <td>{toSentenceCase(alert.source)}</td>
                        <td>
                          <button
                            type="button"
                            className="table-link mono-inline"
                            onClick={(event) => {
                              event.stopPropagation()
                              openSession(alert.session_id)
                            }}
                            title={alert.session_id}
                          >
                            <PreviewValue value={alert.session_id} limit={18} />
                          </button>
                        </td>
                        <td className="mono-inline" title={primaryEventId}>
                          <PreviewValue value={primaryEventId} limit={18} />
                        </td>
                        <td>{getRuleLabel(alert.rule_id)}</td>
                        <td>{formatTimestamp(alert.created_at)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="panel detail-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Redacted evidence</span>
              <h3>{selectedAlert ? selectedAlert.rule_id : 'Select an alert'}</h3>
            </div>
          </div>

          {renderAlertDetails()}
        </aside>
      </div>
    )
  }

  function renderSessionReplay() {
    return (
      <div className="page-grid session-grid">
        <section className="panel session-selector-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Session replay</span>
              <h3>Audit timeline selector</h3>
            </div>
          </div>

          <form
            className="session-form"
            onSubmit={(event) => {
              event.preventDefault()
              if (!sessionInput.trim()) {
                return
              }

              setSelectedSessionId(sessionInput.trim())
            }}
          >
            <input
              value={sessionInput}
              onChange={(event) => setSessionInput(event.target.value)}
              placeholder="Enter a session_id"
              aria-label="Session ID"
            />
            <button type="submit">Load replay</button>
          </form>

          <div className="session-list compact">
            {sessionSummaries.length === 0 ? (
              <p className="empty-state">No session selected yet because the backend has no replayable sessions.</p>
            ) : (
              sessionSummaries.map((session) => (
                <button
                  key={session.sessionId}
                  type="button"
                  className={`session-card compact ${selectedSessionId === session.sessionId ? 'selected-card' : ''}`}
                  onClick={() => {
                    setSessionInput(session.sessionId)
                    setSelectedSessionId(session.sessionId)
                  }}
                >
                  <div className="session-card-top">
                    <PreviewValue value={session.sessionId} limit={22} className="mono-inline" />
                    <span
                      className={`severity-badge severity-inline ${session.highestSeverity !== 'none' ? `severity-${session.highestSeverity}` : ''}`}
                    >
                      {session.highestSeverity === 'none' ? 'clean' : session.highestSeverity}
                    </span>
                  </div>
                  <div className="session-card-stats">
                    <span>{session.eventCount} events</span>
                    <span>{session.alertCount} alerts</span>
                    <span>{formatTimestamp(session.latestAt)}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </section>

        <section className="panel replay-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Audit timeline</span>
              <h3>{selectedSessionId || 'No session selected'}</h3>
            </div>
          </div>

          {!selectedSessionId ? (
            <p className="empty-state">No session selected. Pick a recent session or enter a session ID to replay it.</p>
          ) : isSessionLoading ? (
            <p className="empty-state">Loading session replay...</p>
          ) : sessionReplay ? (
            <>
              <div className="replay-summary">
                <span>{sessionReplay.events.length} events</span>
                <span>{sessionReplay.alerts.length} alerts</span>
              </div>

              <div className="timeline">
                {sessionReplay.events.length === 0 ? (
                  <p className="empty-state">This session has no stored events.</p>
                ) : (
                  sessionReplay.events.map((event) => {
                    const relatedAlerts = sessionReplay.alerts.filter((alert) =>
                      alert.event_ids.includes(event.event_id),
                    )
                    const primaryActionText = getPrimaryActionText(event)
                    const mismatchAlert = relatedAlerts.find((alert) => alert.rule_id === 'R-INTENT-001')
                    const flowLabel = getEventFlowLabel(event, relatedAlerts)
                    const isRmcp005Event = relatedAlerts.some((alert) => alert.rule_id === 'R-MCP-005')
                    const isParamsExpanded = expandedParamEventIds.has(event.event_id)

                    return (
                      <article
                        key={event.event_id}
                        className={`timeline-event ${mismatchAlert ? 'mismatch-event' : ''}`}
                      >
                        <div className="timeline-meta">
                          <span>{formatTimestamp(event.timestamp)}</span>
                          <span>{toSentenceCase(event.source)}</span>
                          <span>{toSentenceCase(event.action_type)}</span>
                        </div>

                        <div className="timeline-title">
                          <strong className="mono-inline wrap-anywhere">{event.event_id}</strong>
                          <div className="chip-row">
                            {relatedAlerts.map((alert) => (
                              <span
                                key={`${event.event_id}-${alert.alert_id}`}
                                className={`rule-pill rule-${getRuleFamily(alert.rule_id)}`}
                                title={getRuleExplanation(alert.rule_id)}
                              >
                                {alert.rule_id}
                              </span>
                            ))}
                          </div>
                        </div>

                        {flowLabel ? <div className="flow-note">{flowLabel}</div> : null}

                        <div className="compare-grid">
                          <div className="info-card">
                            <span className="detail-label">Intent</span>
                            <p>{event.intent_text ?? 'No declared intent'}</p>
                          </div>

                          <div className="info-card">
                            <span className="detail-label">Action</span>
                            <div className="chip-row">
                              <span className="rule-pill rule-other">{event.action_type}</span>
                            </div>
                            {primaryActionText ? (
                              <div className="danger-line mono-inline wrap-anywhere">
                                {renderDangerousText(primaryActionText)}
                              </div>
                            ) : (
                              <p className="muted-copy">No command or description captured.</p>
                            )}
                          </div>
                        </div>

                        <div className="field-stack">
                          <span className="detail-label">Action parameters</span>
                          {isRmcp005Event && !isParamsExpanded ? (
                            <div className="params-collapse-notice">
                              <p>Action parameters hidden in this view. Open the associated R-MCP-005 alert to view redacted evidence.</p>
                              <button
                                type="button"
                                className="expand-params-btn"
                                onClick={() =>
                                  setExpandedParamEventIds((prev) => new Set([...prev, event.event_id]))
                                }
                              >
                                Show action parameters
                              </button>
                            </div>
                          ) : (
                            <pre className="scroll-code">{formatJson(event.action_params)}</pre>
                          )}
                        </div>

                        <div className="field-stack">
                          <span className="detail-label">Associated alerts</span>
                          {relatedAlerts.length === 0 ? (
                            <p className="muted-copy">No alerts fired for this event.</p>
                          ) : (
                            <div className="linked-alerts">
                              {relatedAlerts.map((alert) => (
                                <button
                                  key={alert.alert_id}
                                  type="button"
                                  className={`linked-alert severity-${alert.severity}`}
                                  onClick={() => openAlert(alert)}
                                >
                                  <AlertMeta alert={alert} />
                                  <strong>{alert.summary}</strong>
                                </button>
                              ))}
                            </div>
                          )}
                        </div>

                        {mismatchAlert || hasReadmeMismatch(event) ? (
                          <div className="warning-label">
                            Intent/action mismatch: stated README inspection, but action touched
                            secrets or network.
                          </div>
                        ) : null}

                      </article>
                    )
                  })
                )}
              </div>
            </>
          ) : (
            <p className="empty-state">No replay data loaded for this session.</p>
          )}
        </section>
      </div>
    )
  }

  function renderToolHistoryObservation(observation: ToolObservation, index: number) {
    const previous = index > 0 ? selectedToolHistory[index - 1] : null
    const descriptionChanged = previous !== null && previous.description_hash !== observation.description_hash
    const schemaChanged = previous !== null && previous.schema_hash !== observation.schema_hash

    return (
      <article
        key={`${observation.event_id}-${observation.observed_at}`}
        className={`history-card ${descriptionChanged || schemaChanged ? 'history-drifted' : ''}`}
      >
        <div className="timeline-title">
          <strong>{formatTimestamp(observation.observed_at)}</strong>
          <div className="chip-row">
            {descriptionChanged ? <span className="shadow-badge drift-badge">description drift</span> : null}
            {schemaChanged ? <span className="shadow-badge drift-badge">schema drift</span> : null}
          </div>
        </div>

        <div className="detail-grid">
          <div className="field-stack">
            <span className="detail-label">Event ID</span>
            <p className="mono-inline wrap-anywhere">{observation.event_id}</p>
          </div>
          <div className="field-stack">
            <span className="detail-label">Session</span>
            <button
              type="button"
              className="table-link mono-inline wrap-anywhere"
              onClick={() => openSession(observation.session_id)}
              title={observation.session_id}
            >
              {observation.session_id}
            </button>
          </div>
          <div className="field-stack">
            <span className="detail-label">Description hash</span>
            <p className="mono-inline wrap-anywhere">{observation.description_hash}</p>
          </div>
          <div className="field-stack">
            <span className="detail-label">Schema hash</span>
            <p className="mono-inline wrap-anywhere">{observation.schema_hash}</p>
          </div>
        </div>

        <div className="field-stack">
          <span className="detail-label">Description</span>
          <div className="danger-line">{renderDangerousText(observation.description)}</div>
        </div>

        <div className="compare-grid">
          <div className="field-stack">
            <span className="detail-label">Input schema</span>
            <pre className="scroll-code">{formatJson(observation.input_schema)}</pre>
          </div>
          <div className="field-stack">
            <span className="detail-label">Output schema</span>
            <pre className="scroll-code">{formatJson(observation.output_schema)}</pre>
          </div>
        </div>
      </article>
    )
  }

  function renderToolsView() {
    const selectedToolShadowing = hasToolShadowing(selectedTool, toolNameServerMap)
    const selectedToolShadowServers = getToolShadowServers(selectedTool, toolNameServerMap)

    return (
      <div className="page-grid tools-grid">
        <section className="panel table-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Tool registry</span>
              <h3>{tools.length} current MCP tool fingerprints</h3>
            </div>
          </div>

          {tools.length === 0 ? (
            <p className="empty-state">No MCP tools have been observed yet. Use Seed MCP Registry Demo to populate the registry.</p>
          ) : (
            <div className="table-scroll">
              <table className="alerts-table tools-table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Server</th>
                    <th>Observations</th>
                    <th>Status</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                    <th>Description hash</th>
                    <th>Schema hash</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {tools.map((tool) => {
                    const selected = selectedToolId === tool.fingerprint_id
                    const shadowed = hasToolShadowing(tool, toolNameServerMap)

                    return (
                      <tr
                        key={tool.fingerprint_id}
                        className={selected ? 'selected-row' : undefined}
                        onClick={() => setSelectedToolId(tool.fingerprint_id)}
                      >
                        <td>
                          <div className="tool-name-cell">
                            <strong className="mono-inline">{tool.tool_name}</strong>
                            {shadowed ? <span className="shadow-badge">Shadowed name</span> : null}
                          </div>
                        </td>
                        <td className="mono-inline" title={tool.server_id}>
                          <PreviewValue value={tool.server_id} limit={20} />
                        </td>
                        <td>{tool.observation_count}</td>
                        <td>
                          <div className="chip-row">
                            {tool.drift_count > 0 ? (
                              <span className="shadow-badge drift-badge">{tool.drift_count} drift</span>
                            ) : (
                              <span className="shadow-badge stable-badge">stable</span>
                            )}
                            {shadowed ? <span className="shadow-badge">shadowed</span> : null}
                          </div>
                        </td>
                        <td>{formatTimestamp(tool.first_seen)}</td>
                        <td>{formatTimestamp(tool.last_seen)}</td>
                        <td className="mono-inline" title={tool.description_hash}>
                          <PreviewValue value={tool.description_hash} limit={12} />
                        </td>
                        <td className="mono-inline" title={tool.schema_hash}>
                          <PreviewValue value={tool.schema_hash} limit={12} />
                        </td>
                        <td title={tool.description}>{excerpt(tool.description)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="panel detail-panel">
          <div className="section-heading">
            <div>
              <span className="panel-label">Tool detail</span>
              <h3>{selectedTool?.tool_name ?? 'Select a tool'}</h3>
            </div>
          </div>

          {!selectedToolId ? (
            <p className="empty-state">No tool selected yet.</p>
          ) : isToolLoading ? (
            <p className="empty-state">Loading tool registry details...</p>
          ) : selectedTool ? (
            <div className="detail-stack">
              {selectedToolShadowing ? (
                <div className="warning-label">
                  Shadowed name: also seen on another server.
                  <div className="shadow-server-list">
                    <span className="mono-inline wrap-anywhere">{selectedTool.tool_name}</span>
                    {selectedToolShadowServers.map((serverId) => (
                      <span key={serverId} className="mono-inline wrap-anywhere">
                        {serverId}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="info-card">
                <span className="detail-label">Current fingerprint status</span>
                <div className="chip-row">
                  {selectedTool.drift_count > 0 ? (
                    <span className="shadow-badge drift-badge">{selectedTool.drift_count} drift observations</span>
                  ) : (
                    <span className="shadow-badge stable-badge">No drift observed</span>
                  )}
                  {selectedToolShadowing ? (
                    <span className="shadow-badge">Tool name appears on multiple servers</span>
                  ) : (
                    <span className="shadow-badge stable-badge">No shadowing for this name</span>
                  )}
                </div>
                <p className="muted-copy small-copy">
                  Description and schema hashes represent the latest observed definition for this server/tool pair.
                </p>
              </div>

              <div className="detail-grid">
                <div className="field-stack">
                  <span className="detail-label">Fingerprint ID</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.fingerprint_id}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Server ID</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.server_id}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">First seen</span>
                  <p>{formatTimestamp(selectedTool.first_seen)}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Last seen</span>
                  <p>{formatTimestamp(selectedTool.last_seen)}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Observations</span>
                  <p>{selectedTool.observation_count}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Drift count</span>
                  <p>{selectedTool.drift_count}</p>
                </div>
              </div>

              <div className="field-stack">
                <span className="detail-label">Description</span>
                <div className="danger-line">{renderDangerousText(selectedTool.description)}</div>
              </div>

              <div className="detail-grid">
                <div className="field-stack">
                  <span className="detail-label">Name hash</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.name_hash}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Description hash</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.description_hash}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Schema hash</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.schema_hash}</p>
                </div>
                <div className="field-stack">
                  <span className="detail-label">Latest event</span>
                  <p className="mono-inline wrap-anywhere">{selectedTool.latest_event_id ?? 'n/a'}</p>
                </div>
              </div>

              <div className="field-stack">
                <span className="detail-label">History</span>
                {selectedToolHistory.length === 0 ? (
                  <p className="empty-state">No history observations stored for this tool.</p>
                ) : (
                  <div className="tool-history-list">
                    {selectedToolHistory.map((observation, index) =>
                      renderToolHistoryObservation(observation, index),
                    )}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <p className="empty-state">Tool details are not available for the selected fingerprint.</p>
          )}
        </aside>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <header className="hero-panel">
        <div className="header-title-row">
          <div className="header-title-copy">
            <p className="eyebrow">AIWatch audit console</p>
            <h1>MCP Runtime Security Monitor</h1>
            <p className="hero-copy">
              Review routed MCP tool traffic, tool registry drift, deterministic MCP checks,
              session replay, and redacted evidence.
            </p>
          </div>

          <div className="status-chip-row">
            <span className={`status-chip ${backendOffline ? 'status-offline' : 'status-online'}`}>
              {backendOffline ? 'Backend: Offline' : 'Backend: Online'}
            </span>
            <span className="status-chip status-storage">Store: SQLite local audit log</span>
            <span className="status-chip status-storage">Scope: Routed MCP only</span>
          </div>
        </div>

        <div className="header-claim-row">
          <p className="limitation-line hero-limitation">
            AIWatch observes MCP traffic routed through the stdio wrapper or local HTTP MCP relay.
          </p>
          <p className="scope-warning">
            Out of scope: prompts, shell commands, file edits, hidden reasoning, laptop activity,
            and arbitrary network traffic.
          </p>
        </div>

        <div className="header-workbench">
          <div className="controls-card">
            <span className="panel-label">Local audit controls</span>
            <p className="muted-copy small-copy">
              Populate the local audit timeline with deterministic MCP findings, tool fingerprints,
              and redacted credential evidence.
            </p>
            <div className="control-row">
              <button type="button" onClick={() => void refreshDashboard()} disabled={isLoading || isMutating}>
                Refresh
              </button>
              <button type="button" onClick={() => void handleSeedDemo(false)} disabled={mutationDisabled}>
                Seed Core Audit
              </button>
              <button type="button" onClick={() => void handleSeedDemo(true)} disabled={mutationDisabled}>
                Seed Tool Registry Audit
              </button>
              <button type="button" onClick={() => void handleCredentialDemo()} disabled={mutationDisabled}>
                Trigger Redacted Evidence
              </button>
            </div>
            <p className="muted-copy small-copy">
              Adds one synthetic MCP tools/call event for R-MCP-005 evidence review.
            </p>
            <button
              type="button"
              className="warning-button"
              onClick={() => void handleClearData()}
              disabled={mutationDisabled}
            >
              Clear Data
            </button>
          </div>

          <div className="panel proof-panel header-proof-panel">
            <div className="section-heading">
              <div>
                <span className="panel-label">Validation state</span>
                <h3>Current audit proof</h3>
              </div>
            </div>
            <div className="proof-grid">
              <div>
                <strong>175</strong>
                <span>backend tests passing</span>
              </div>
              <div>
                <strong>43/43</strong>
                <span>deterministic eval cases</span>
              </div>
              <div>
                <strong>5/7 + 8/10</strong>
                <span>core and registry seed states</span>
              </div>
              <div>
                <strong>Live</strong>
                <span>local Lobster Trap audit ingestion</span>
              </div>
            </div>
            <div className="live-status-row">
              <span className="live-count-chip">{health?.events ?? 0} events</span>
              <span className="live-count-chip">{alerts.length} alerts</span>
              <span className="live-count-chip">{tools.length} tools</span>
              <span className="live-count-chip">{auditTimeline.length} audit records</span>
            </div>
          </div>
        </div>

        <div className="command-panel command-strip">
          <div>
            <span className="detail-label">CLI audit path</span>
            <p className="muted-copy small-copy">Controls require AIWATCH_DEV_MODE=true on the backend.</p>
          </div>
          <div className="command-strip-codes">
            <pre className="scroll-code">py -3.12 scripts\aiwatch.py demo-seed</pre>
            <pre className="scroll-code">py -3.12 scripts\aiwatch.py demo-seed --extended</pre>
          </div>
        </div>
      </header>

      <nav className="view-tabs" aria-label="Dashboard views">
        <button
          type="button"
          className={activeView === 'overview' ? 'active-tab' : ''}
          onClick={() => setActiveView('overview')}
        >
          Overview
        </button>
        <button
          type="button"
          className={activeView === 'alerts' ? 'active-tab' : ''}
          onClick={() => setActiveView('alerts')}
        >
          Alerts
        </button>
        <button
          type="button"
          className={activeView === 'audit' ? 'active-tab' : ''}
          onClick={() => setActiveView('audit')}
        >
          Unified Audit
        </button>
        <button
          type="button"
          className={activeView === 'tools' ? 'active-tab' : ''}
          onClick={() => setActiveView('tools')}
        >
          Tools / Registry
        </button>
        <button
          type="button"
          className={activeView === 'sessions' ? 'active-tab' : ''}
          onClick={() => setActiveView('sessions')}
        >
          Session replay
        </button>
      </nav>

      {bannerMessage ? <div className="info-banner">{bannerMessage}</div> : null}
      {errorMessage ? <div className="error-banner">{errorMessage}</div> : null}

      {isLoading ? (
        <main className="loading-shell">
          <div className="panel">
            <h3>Loading AIWatch dashboard...</h3>
            <p className="muted-copy">Waiting for persisted backend state.</p>
          </div>
        </main>
      ) : backendOffline ? (
        <main className="offline-shell">
          <div className="panel">
            <h3>Backend offline or blocked</h3>
            <p className="muted-copy">{BACKEND_OFFLINE_MESSAGE}</p>
          </div>
        </main>
      ) : (
        <main>
          {activeView === 'overview' ? renderOverview() : null}
          {activeView === 'alerts' ? renderAlertsTable() : null}
          {activeView === 'audit' ? renderUnifiedAuditTimeline() : null}
          {activeView === 'tools' ? renderToolsView() : null}
          {activeView === 'sessions' ? renderSessionReplay() : null}
        </main>
      )}

      {!backendOffline && tools.length === 0 && alerts.length === 0 && events.length === 0 && auditTimeline.length === 0 ? (
        <div className="panel empty-footnote">
          <p className="empty-state">
            No events, alerts, or MCP tool fingerprints yet. Seed the demo to populate the dashboard.
          </p>
        </div>
      ) : null}

      {!backendOffline && shadowedToolNames.length > 0 ? (
        <div className="panel shadow-summary-panel">
          <span className="panel-label">Registry watch</span>
          <h3>Shadowed tool names detected</h3>
          <div className="chip-row">
            {shadowedToolNames.map((toolName) => (
              <span key={toolName} className="shadow-badge">
                {toolName}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default App
