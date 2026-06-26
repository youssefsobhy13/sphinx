-- ============================================================
-- SPHINX UNIVERSITY — DATABASE SETUP + ROW LEVEL SECURITY (RLS)
-- Run this once in the Supabase SQL Editor (Project > SQL Editor)
-- ============================================================
-- WHY THIS FILE EXISTS:
-- The old admin.html checked a hardcoded phone/password IN THE
-- BROWSER. That is not security — anyone can read it in
-- "View Page Source" or just call the Supabase REST API directly
-- with curl/Postman and skip the password screen entirely.
--
-- Real protection has to live in the DATABASE, enforced by
-- Postgres itself, no matter what request hits it or from where.
-- That's what Row Level Security (RLS) policies below do.
-- ============================================================

-- 1. USERS TABLE -------------------------------------------------
create table if not exists public.users (
  id              uuid primary key references auth.users(id) on delete cascade,
  full_name       text not null,
  father_name     text default '',
  phone           text unique,
  university_id   text unique,
  email           text unique,
  profile_picture text default '',
  total_points    integer default 0,
  study_sessions  integer default 0,
  achievements    jsonb default '[]'::jsonb,
  progress        jsonb default '{"networks":0,"architecture":0,"dsa":0}'::jsonb,
  created_at      timestamptz default now(),
  updated_at      timestamptz default now(),
  last_login      timestamptz default now(),
  is_admin        boolean default false,
  is_vip          boolean default false,
  is_guest        boolean default false,
  is_disabled     boolean default false
);

-- 2. ACTIVITY LOG (for the admin "Activity Log" feature) ---------
create table if not exists public.admin_activity_log (
  id          bigint generated always as identity primary key,
  admin_id    uuid references auth.users(id),
  action      text not null,
  target_user uuid references public.users(id),
  details     jsonb default '{}'::jsonb,
  created_at  timestamptz default now()
);

-- 3. LOGIN ATTEMPTS (for lockout / throttling) --------------------
create table if not exists public.login_attempts (
  id          bigint generated always as identity primary key,
  identifier  text not null,            -- phone, university_id, or email used
  success     boolean not null,
  ip_hint     text,
  created_at  timestamptz default now()
);

-- 4. ENABLE RLS ----------------------------------------------------
alter table public.users enable row level security;
alter table public.admin_activity_log enable row level security;
alter table public.login_attempts enable row level security;

-- 5. HELPER: is the CURRENT authenticated user an admin? -----------
-- SECURITY DEFINER lets this check the table once, bypassing RLS
-- recursion, then every policy below can safely call it.
create or replace function public.is_current_user_admin()
returns boolean
language sql
security definer
set search_path = public
as $$
  select coalesce(
    (select is_admin from public.users where id = auth.uid()),
    false
  );
$$;

-- 6. USERS TABLE POLICIES -------------------------------------------

-- Anyone signed in can read their OWN row.
create policy "users_select_own"
  on public.users for select
  using (auth.uid() = id);

-- Admins can read EVERY row (needed for admin.html user list).
create policy "users_select_admin"
  on public.users for select
  using (public.is_current_user_admin());

-- Public/anon read for leaderboard purposes only — limited columns
-- are exposed via the `leaderboard_public` view below instead of
-- opening the whole table; this policy is intentionally NOT added
-- for raw `users` table anon access.

-- A user can update their OWN row, but can NEVER promote themselves.
-- The WITH CHECK clause blocks any update that changes is_admin,
-- is_vip, or is_disabled away from what they currently have.
create policy "users_update_own"
  on public.users for update
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    and is_admin   = (select is_admin   from public.users where id = auth.uid())
    and is_vip     = (select is_vip     from public.users where id = auth.uid())
    and is_disabled= (select is_disabled from public.users where id = auth.uid())
  );

-- Admins can update ANY row, including roles.
create policy "users_update_admin"
  on public.users for update
  using (public.is_current_user_admin());

-- New row creation happens during signup — a user may only insert
-- a row matching their own auth id, and may never insert themselves
-- as admin/vip.
create policy "users_insert_self"
  on public.users for insert
  with check (
    auth.uid() = id
    and is_admin = false
    and is_vip = false
  );

-- Only admins can delete user rows.
create policy "users_delete_admin"
  on public.users for delete
  using (public.is_current_user_admin());

-- 7. LEADERBOARD — a safe public view (no email/phone exposed) -----
create or replace view public.leaderboard_public as
  select id, full_name, profile_picture, total_points, is_vip
  from public.users
  where is_guest = false and is_disabled = false
  order by total_points desc;

-- Allow anyone (including anon) to read the leaderboard view only.
grant select on public.leaderboard_public to anon, authenticated;

-- 8. ACTIVITY LOG POLICIES ------------------------------------------
create policy "activity_log_admin_only_select"
  on public.admin_activity_log for select
  using (public.is_current_user_admin());

create policy "activity_log_admin_only_insert"
  on public.admin_activity_log for insert
  with check (public.is_current_user_admin());

-- 9. LOGIN ATTEMPTS POLICIES -----------------------------------------
-- Inserts are allowed from anyone (we log attempts before/without
-- auth), but only admins can read the log back.
create policy "login_attempts_insert_anyone"
  on public.login_attempts for insert
  with check (true);

create policy "login_attempts_select_admin"
  on public.login_attempts for select
  using (public.is_current_user_admin());

-- 10. AUTO-UPDATE updated_at -------------------------------------------
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_users_updated_at on public.users;
create trigger trg_users_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

-- 11. MAKING YOUR FIRST ADMIN ACCOUNT ----------------------------------
-- RLS now blocks anyone from setting is_admin=true on themselves or
-- anyone else through the app. The ONLY way to create the first admin
-- is to run this manually, once, here in the SQL editor (which runs
-- with full database owner rights, bypassing RLS):
--
--   update public.users set is_admin = true where phone = '01066781530';
--
-- Run that line yourself after the matching user has signed up through
-- login.html. After that, this first admin can promote others safely
-- from inside admin.html (which uses the authenticated admin's own
-- session to satisfy the "users_update_admin" policy above).
