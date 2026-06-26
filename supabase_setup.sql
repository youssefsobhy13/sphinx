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
-- is_vip, or is_disabled by comparing against the OLD row values
-- (read via a security-definer helper, since the user can't read
-- their own pre-update row mid-statement otherwise).
create or replace function public.get_my_current_roles()
returns table(is_admin boolean, is_vip boolean, is_disabled boolean)
language sql
security definer
set search_path = public
stable
as $$
  select is_admin, is_vip, is_disabled from public.users where id = auth.uid();
$$;

create policy "users_update_own"
  on public.users for update
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    and is_admin    = (select is_admin    from public.get_my_current_roles())
    and is_vip      = (select is_vip      from public.get_my_current_roles())
    and is_disabled = (select is_disabled from public.get_my_current_roles())
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

-- 7b. PRE-LOGIN HELPERS ----------------------------------------------
-- These two functions exist because RLS correctly blocks a logged-out
-- (or not-yet-this-user) visitor from reading ANY row in `users`.
-- But login.html needs two narrow things that aren't security risks
-- on their own, as long as they reveal nothing except what's needed:
--
--   a) "what email goes with this phone/university_id?" — needed so
--      a user can sign in with phone or ID instead of typing email.
--   b) "does this phone/university_id/email already exist?" — needed
--      so signup can reject duplicates with a clear message instead
--      of a generic Postgres unique-constraint error.
--
-- Both run as SECURITY DEFINER (bypassing RLS internally) but only
-- return the minimum needed, and only via RPC — they are never able
-- to be used to browse the table.

create or replace function public.lookup_email_for_login(
  p_column text,    -- must be 'phone' or 'university_id'
  p_value  text
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text;
begin
  if p_column not in ('phone', 'university_id') then
    raise exception 'Invalid lookup column';
  end if;

  if p_column = 'phone' then
    select email into v_email from public.users where phone = p_value and is_disabled = false limit 1;
  else
    select email into v_email from public.users where university_id = p_value and is_disabled = false limit 1;
  end if;

  return v_email; -- null if not found; caller treats null as "not found"
end;
$$;

-- Anyone (even logged out / anon) needs to call this during login.
grant execute on function public.lookup_email_for_login(text, text) to anon, authenticated;

create or replace function public.check_signup_duplicate(
  p_phone   text,
  p_univ_id text,
  p_email   text
)
returns boolean  -- true = a duplicate exists somewhere
language sql
security definer
set search_path = public
as $$
  select exists(
    select 1 from public.users
    where phone = p_phone or university_id = p_univ_id or email = p_email
  );
$$;

grant execute on function public.check_signup_duplicate(text, text, text) to anon, authenticated;

create or replace function public.lookup_guest_account(p_university_id text)
returns uuid  -- returns the existing guest's auth id, or null
language sql
security definer
set search_path = public
as $$
  select id from public.users
  where university_id = p_university_id and is_guest = true
  limit 1;
$$;

grant execute on function public.lookup_guest_account(text) to anon, authenticated;

-- 7c. AUTO-CREATE PROFILE ROW ON SIGNUP (fixes the RLS + email-
-- confirmation interaction) -----------------------------------------
-- WHY THIS IS NEEDED:
-- login.html's signup flow calls supabaseClient.auth.signUp(), then
-- immediately tries to INSERT a row into public.users using the
-- new user's id. That insert only succeeds if auth.uid() is already
-- active for that request — but if your Supabase project has email
-- confirmation ENABLED (Authentication > Providers > Email > Confirm
-- email), signUp() does NOT create an active session until the link
-- in the confirmation email is clicked. So the insert silently fails
-- under RLS, and the signup looks "successful" in the UI but no
-- profile row ever gets created — the user then can't log in
-- properly because there's no row to read their data from.
--
-- The fix: create the profile row from a trigger ON THE SERVER the
-- moment the auth.users row is created, using the metadata passed
-- in signUp()'s `options.data`. This works identically whether email
-- confirmation is on or off, and the client no longer needs to (and
-- should not) insert into public.users directly during signup.

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_university_id text;
begin
  -- university_id is UNIQUE, so we can never insert an empty string
  -- for more than one user (Google OAuth sign-ins don't provide one
  -- at signup time). Fall back to a per-user unique placeholder
  -- instead of '' when none was supplied.
  v_university_id := nullif(new.raw_user_meta_data->>'university_id', '');
  if v_university_id is null then
    v_university_id := 'PENDING-' || substr(new.id::text, 1, 8);
  end if;

  insert into public.users (
    id, full_name, father_name, phone, university_id, email,
    total_points, study_sessions, achievements, progress,
    created_at, updated_at, last_login, is_admin, is_vip, is_guest
  )
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', 'Student'),
    coalesce(new.raw_user_meta_data->>'father_name', ''),
    coalesce(new.raw_user_meta_data->>'phone', ''),
    v_university_id,
    new.email,
    0, 0, '[]'::jsonb, '{"networks":0,"architecture":0,"dsa":0}'::jsonb,
    now(), now(), now(), false, false, false
  )
  on conflict (id) do nothing; -- in case a row was already created (e.g. guest flow)
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row
  when (new.is_anonymous is not true) -- guests are handled by login.html itself, not this trigger
  execute function public.handle_new_auth_user();

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

-- 12. PROFILE PICTURE STORAGE (fixes "profile picture disappears") --
-- WHY THIS IS NEEDED:
-- index.html already calls supabase.storage.from('profile-pictures')
-- .upload(...) when someone changes their photo. That call FAILS
-- silently (caught and only console.warn'd) if the bucket doesn't
-- exist yet, or if Storage's own RLS doesn't allow the upload —
-- which looks exactly like "the picture disappears" because nothing
-- ever actually got saved to Storage in the first place; the app
-- was just showing the local preview from FileReader until the page
-- reloaded and there was nothing real to load back.

insert into storage.buckets (id, name, public)
values ('profile-pictures', 'profile-pictures', true)
on conflict (id) do nothing;

-- A user may upload/update/delete only files inside their own
-- "avatars/<their-uid>.*" path — enforced by checking the path
-- against their own auth.uid(), not by trusting the filename alone.
create policy "avatar_upload_own"
  on storage.objects for insert
  with check (
    bucket_id = 'profile-pictures'
    and (storage.foldername(name))[1] = 'avatars'
    and split_part(storage.filename(name), '.', 1) = auth.uid()::text
  );

create policy "avatar_update_own"
  on storage.objects for update
  using (
    bucket_id = 'profile-pictures'
    and (storage.foldername(name))[1] = 'avatars'
    and split_part(storage.filename(name), '.', 1) = auth.uid()::text
  );

create policy "avatar_delete_own"
  on storage.objects for delete
  using (
    bucket_id = 'profile-pictures'
    and (storage.foldername(name))[1] = 'avatars'
    and split_part(storage.filename(name), '.', 1) = auth.uid()::text
  );

-- Bucket is public, so reading photos back (to display them) needs
-- no special policy — anyone with the URL can view, the same way
-- any public CDN image works. This matches how avatars are shown
-- everywhere in index.html/admin.html via a plain <img src>.
create policy "avatar_public_read"
  on storage.objects for select
  using (bucket_id = 'profile-pictures');
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
