export interface Identity {
  issuer: string;
  subject: string;
  name: string;
  display_name: string;
  email?: string;
  admin: boolean;
}

export interface BrowserSession {
  user: Identity;
  owner_id: string;
  csrf_token: string;
  expires_at: string;
}

export interface Session {
  id: string;
  owner: string;
  name: string;
  display_name: string;
  email?: string;
  cluster: string;
  state: 'ACTIVE' | 'RELEASED' | 'EXPIRED';
  created_at: string;
  ended_at?: string;
  expires_at?: string;
  last_activity_at?: string;
  reason: string;
  primary: boolean;
}

export interface Cluster {
  id: string;
  name: string;
  labels: Record<string, string>;
  maintenance: boolean;
  controller_session?: string;
  shareable: boolean;
  max_participants: number;
  participants: Session[];
  available: boolean;
  reason: string;
  deregistered_at?: string;
  lifecycle_holds?: number;
  health?: ClusterHealth;
  registry_version: number;
  configuration_generation?: number;
  health_policy_revision?: number;
  health_profile?: HealthProfile;
}

export type HealthProfile = 'api-ready.v1' | 'discovery-only.v1';
export interface ClusterHealth {
  state: 'UNKNOWN' | 'RECOVERING' | 'PASSING' | 'FAILING' | 'STALE';
  profile: HealthProfile;
  reason_code: string;
  checked_at?: string;
  last_success_at?: string;
  duration_ms: number;
  max_age_seconds: number;
  consecutive_successes: number;
  readiness_confirmed: boolean;
  discovery_coverage: string;
  identity_verification: string;
  check_pending: boolean;
  next_check_at?: string;
  configuration_generation: number;
  policy_revision: number;
  components?: Array<{name: string; state: string; reason_code: string; http_status?: number; duration_ms: number}>;
}

export interface DeveloperProfile {
  owner_id: string;
  user: Identity;
  max_bookings: number;
  max_bookings_override?: number | null;
  active_bookings: number;
  primary_session?: Session | null;
  selection_version: number;
}

export interface AutoBookingPolicy {
  enabled: boolean;
  selector: Record<string, string>;
}

export interface PAT {
  id: string;
  owner: string;
  name: string;
  scope: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  last_used_at?: string;
  auto_booking: AutoBookingPolicy;
}

export interface Settings {
  default_max_bookings: number;
  inactivity_grace_period: string;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor: string;
  action: string;
  object_id: string;
  detail: string;
}

export interface Workspace {
  session: BrowserSession;
  profile: DeveloperProfile;
  clusters: Cluster[];
  sessions: Session[];
  pats: PAT[];
  allPats: PAT[];
  settings: Settings | null;
  developers: DeveloperProfile[];
  audit: AuditEvent[];
}

export interface ApiOptions {
  cache?: RequestCache;
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}
export type ApiClient = <T = unknown>(path: string, options?: ApiOptions) => Promise<T>;
export type Notify = (message: string, error?: boolean) => void;
export type Section = 'overview' | 'clusters' | 'access' | 'admin-clusters' | 'admin-people' | 'admin-tokens' | 'admin-audit' | 'admin-webhooks';

export interface PageProps {
  data: Workspace;
  api: ApiClient;
  refresh: () => Promise<void>;
  notify: Notify;
  navigate: (section: Section) => void;
  requestBooking: (cluster: string) => void;
  selectedBookingCluster?: string;
  bookingRequestVersion?: number;
}

export interface WebhookRule {
  id: string;
  name: string;
  url: string;
  events: string[];
  cluster_id: string;
  selector: Record<string, string>;
  blocking: boolean;
  idempotent: boolean;
  enabled: boolean;
  timeout_seconds: number;
  version: number;
}
export interface WebhookEventType {name: string; description: string; cluster: boolean; blocking: boolean}
export interface WebhookCatalogue {rules: WebhookRule[]; events: WebhookEventType[]; allowed_origins: string[]}
export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  event_id: number;
  cluster_id: string;
  state: string;
  reason_code: string;
  blocking: boolean;
  attempts: number;
  http_status?: number;
  created_at: string;
  updated_at: string;
  deadline: string;
}
