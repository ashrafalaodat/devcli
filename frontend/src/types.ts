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
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}
export type ApiClient = <T = unknown>(path: string, options?: ApiOptions) => Promise<T>;
export type Notify = (message: string, error?: boolean) => void;
export type Section = 'overview' | 'clusters' | 'access' | 'admin-clusters' | 'admin-people' | 'admin-tokens' | 'admin-audit';

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
