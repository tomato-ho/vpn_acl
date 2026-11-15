export interface UserRow {
  username: string
  display_name: string
  group: string
  fixed_ip: string
  enabled: boolean
  must_change_password: boolean
  created_at: string
  updated_at: string
}

export interface GroupRow {
  id: number
  name: string
  ip_start: string
  ip_end: string
  description: string
  user_count: number
  rule_count: number
}

export interface UserRule {
  id: number
  rule_type: string
  cidr: string
  enabled: boolean
  created_at?: string
}

export interface GroupRule {
  id: number
  rule_type: string
  cidr: string
  enabled: boolean
  created_at?: string
}

export interface GroupDetail extends GroupRow {
  rules: GroupRule[]
}

export interface ServiceRow {
  id: number
  scope_type: string
  scope_id: string
  service: string
  enabled: boolean
  created_at: string
}

export interface SettingsValues {
  allowed_target_networks: string
  allowed_service_ips: string
  tunnel_network: string
  max_rules_per_user: string
  max_services_per_user: string
}

export interface HistorySession {
  username: string
  virtual_ip: string
  remote_ip: string
  start_time: string
  stop_time: string
  duration_seconds: number
  bytes_in: number
  bytes_out: number
  terminate_cause: string
  state: string
  user_exists: boolean
}

export interface SessionHistoryStats {
  unique_users: number
  session_count: number
  online_sessions: number
  total_seconds: number
  bytes_in: number
  bytes_out: number
}

export interface AuthFailure {
  id: number
  username: string
  reply: string
  auth_time: string
  user_exists: boolean
}

export interface EffectivePolicy {
  fixed_ip: string
  group: string
  allow: string[]
  deny: string[]
  push_routes: string[]
  services: string[]
}

export interface UserDetail extends UserRow {
  rules: UserRule[]
  policy?: EffectivePolicy
  policy_error?: string
}