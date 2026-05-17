export type Source = 'mcp' | 'coding_agent' | 'http'
export type ActionType =
  | 'tool_call'
  | 'tool_register'
  | 'shell_exec'
  | 'file_read'
  | 'file_write'
  | 'net_egress'
  | 'other'
export type Severity = 'low' | 'medium' | 'high' | 'critical'

export interface AgentEvent {
  event_id: string
  timestamp: string
  agent_id: string
  session_id: string
  source: Source
  intent_text: string | null
  action_type: ActionType
  action_params: Record<string, unknown>
  raw: Record<string, unknown> | null
  parent_event_id: string | null
}

export interface AlertEvidence {
  intent_text: string | null
  action_summary: string
  matched_patterns: string[]
  files_referenced: string[]
  destinations: string[]
  tool_name: string | null
  server_id: string | null
  current_server_id: string | null
  fingerprint_id: string | null
  previous_description_hash: string | null
  current_description_hash: string | null
  previous_schema_hash: string | null
  current_schema_hash: string | null
  previous_description_excerpt: string | null
  current_description_excerpt: string | null
  other_server_ids: string[]
  matching_fingerprint_ids: string[]
  credential_findings: CredentialFinding[]
}

export interface CredentialFinding {
  param_path: string
  secret_type: string
  redacted_value: string
  value_length: number
}

export interface Alert {
  alert_id: string
  created_at: string
  severity: Severity
  rule_id: string
  source: Source
  agent_id: string
  session_id: string
  event_ids: string[]
  summary: string
  rationale: string
  evidence: AlertEvidence
  decision: 'log' | 'block'
}

export interface HealthResponse {
  status: string
  storage?: string
  events: number
  alerts: number
}

export interface SessionReplay {
  session_id: string
  events: AgentEvent[]
  alerts: Alert[]
}

export interface ToolFingerprint {
  fingerprint_id: string
  server_id: string
  tool_name: string
  description: string
  name_hash: string
  description_hash: string
  schema_hash: string
  first_seen: string
  last_seen: string
  observation_count: number
  drift_count: number
  latest_event_id: string | null
}

export interface ToolObservation {
  event_id: string
  fingerprint_id: string
  observed_at: string
  agent_id: string
  session_id: string
  server_id: string
  tool_name: string
  description: string
  name_hash: string
  description_hash: string
  schema_hash: string
  input_schema: Record<string, unknown>
  output_schema: Record<string, unknown>
}

export interface DemoSeedItem {
  name: string
  event_id: string
  alerts_created: number
  rule_ids: string[]
}

export interface DemoSeedResponse {
  status: string
  events_created: number
  alerts_created: number
  tools_observed: number
  items: DemoSeedItem[]
}

export interface EventIngestResponse {
  status: string
  event_id: string
  alerts_created: number
  alerts: Alert[]
}
