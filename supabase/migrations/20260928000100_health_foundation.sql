create table if not exists public.health_connections (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 provider text not null default 'google_health' check(provider='google_health'), google_account_email text,
 access_token text not null, refresh_token text, token_expires_at timestamptz, scopes text[] not null default '{}',
 status text not null default 'connected' check(status in('connected','expired','revoked','error')),
 metadata jsonb not null default '{}'::jsonb,last_error text,last_synced_at timestamptz,created_at timestamptz not null default now(),updated_at timestamptz not null default now(),
 unique(user_id,provider,google_account_email));
alter table public.health_connections enable row level security;
create policy "health_connections_select_own" on public.health_connections for select to authenticated using(auth.uid()=user_id);
create policy "health_connections_delete_own" on public.health_connections for delete to authenticated using(auth.uid()=user_id);

create table if not exists public.health_audit_logs (
 id uuid primary key default gen_random_uuid(),user_id uuid references auth.users(id) on delete set null,
 connection_id uuid references public.health_connections(id) on delete set null,action text not null,status text not null,
 request_id uuid,metadata jsonb not null default '{}'::jsonb,created_at timestamptz not null default now());
alter table public.health_audit_logs enable row level security;
create policy "health_audit_logs_select_own" on public.health_audit_logs for select to authenticated using(auth.uid()=user_id);

create table if not exists public.health_daily_metrics (
 id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users(id) on delete cascade,
 connection_id uuid not null references public.health_connections(id) on delete cascade,metric_date date not null,
 steps bigint,active_minutes numeric,active_zone_minutes numeric,distance_meters numeric,active_energy_kcal numeric,total_energy_kcal numeric,
 resting_heart_rate_bpm numeric,hrv_rmssd_ms numeric,oxygen_saturation_percent numeric,respiratory_rate_bpm numeric,vo2_max numeric,
 sleep_minutes numeric,sleep_start timestamptz,sleep_end timestamptz,source_payload jsonb not null default '{}'::jsonb,synced_at timestamptz not null default now(),
 unique(connection_id,metric_date));
create index health_daily_metrics_user_date_idx on public.health_daily_metrics(user_id,metric_date desc);
alter table public.health_daily_metrics enable row level security;
create policy "health_daily_metrics_select_own" on public.health_daily_metrics for select to authenticated using(auth.uid()=user_id);

create table if not exists public.health_sync_runs (
 id uuid primary key default gen_random_uuid(),user_id uuid not null references auth.users(id) on delete cascade,
 connection_id uuid not null references public.health_connections(id) on delete cascade,status text not null check(status in('running','success','partial','failure')),
 range_start date not null,range_end date not null,metrics_requested text[] not null default '{}',metrics_succeeded text[] not null default '{}',
 errors jsonb not null default '[]'::jsonb,started_at timestamptz not null default now(),finished_at timestamptz);
alter table public.health_sync_runs enable row level security;
create policy "health_sync_runs_select_own" on public.health_sync_runs for select to authenticated using(auth.uid()=user_id);
