-- Huss Huss Huss, update 2: player accounts (username + password), cloud saves, prestige belts.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to run again.
--
-- How accounts work:
--   * Passwords are stored only as bcrypt hashes (pgcrypto).
--   * Logging in returns a random session token; only its SHA-256 hash is stored.
--   * The accounts and sessions tables are unreachable from the browser. Everything goes
--     through the huss_* functions below.
--   * 8 wrong passwords in a row locks that account for 10 minutes.
--   * No email, so no self-service password reset (see the bottom of this file for a manual reset).

create extension if not exists pgcrypto with schema extensions;

-- Leaderboard: belts column, and a flag for rows that belong to accounts
alter table public.scores add column if not exists prestige   integer not null default 0;
alter table public.scores add column if not exists is_account boolean not null default false;

create table if not exists public.accounts (
  id              uuid primary key default gen_random_uuid(),
  username        text not null check (username ~ '^[A-Za-z0-9_]{3,20}$'),
  password_hash   text not null,
  save            jsonb,
  save_updated_at timestamptz,
  failed_logins   integer not null default 0,
  locked_until    timestamptz,
  created_at      timestamptz not null default now()
);
create unique index if not exists accounts_username_lower on public.accounts (lower(username));

create table if not exists public.sessions (
  token_hash bytea primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  expires_at timestamptz not null default now() + interval '180 days'
);

alter table public.accounts enable row level security;
alter table public.sessions enable row level security;
revoke all on public.accounts from anon, authenticated;
revoke all on public.sessions from anon, authenticated;

-- ---------- internal helpers (not callable from the browser) ----------
create or replace function public.huss_new_session(p_account uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(gen_random_bytes(32), 'hex');
begin
  delete from sessions where account_id = p_account and expires_at < now();
  insert into sessions (token_hash, account_id) values (sha256(convert_to(t, 'UTF8')), p_account);
  return t;
end $$;

create or replace function public.huss_account_for(p_token text) returns uuid
language sql stable security definer set search_path = public, extensions as $$
  select account_id from sessions
   where token_hash = sha256(convert_to(coalesce(p_token, ''), 'UTF8')) and expires_at > now();
$$;

revoke all on function public.huss_new_session(uuid) from public, anon, authenticated;
revoke all on function public.huss_account_for(text) from public, anon, authenticated;

-- ---------- sign up ----------
create or replace function public.huss_signup(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u text := btrim(coalesce(p_username, '')); acc uuid;
begin
  if u !~ '^[A-Za-z0-9_]{3,20}$' then
    return json_build_object('error', 'Usernames are 3–20 letters, numbers or underscores.');
  end if;
  if char_length(coalesce(p_password, '')) < 6 then
    return json_build_object('error', 'Passwords need at least 6 characters.');
  end if;
  if char_length(p_password) > 72 then
    return json_build_object('error', 'Passwords can be at most 72 characters.');
  end if;
  if exists (select 1 from accounts where lower(username) = lower(u)) then
    return json_build_object('error', 'That username is taken.');
  end if;
  insert into accounts (username, password_hash) values (u, crypt(p_password, gen_salt('bf', 10)))
  returning id into acc;
  return json_build_object('token', huss_new_session(acc), 'username', u, 'account_id', acc);
exception when unique_violation then
  return json_build_object('error', 'That username is taken.');
end $$;

-- ---------- log in ----------
create or replace function public.huss_login(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare a accounts%rowtype;
begin
  select * into a from accounts where lower(username) = lower(btrim(coalesce(p_username, '')));
  if not found then
    return json_build_object('error', 'Wrong username or password.');
  end if;
  if a.locked_until is not null and a.locked_until > now() then
    return json_build_object('error', 'Too many wrong passwords. Try again in a few minutes.');
  end if;
  if a.password_hash <> crypt(coalesce(p_password, ''), a.password_hash) then
    update accounts
       set failed_logins = case when failed_logins + 1 >= 8 then 0 else failed_logins + 1 end,
           locked_until  = case when failed_logins + 1 >= 8 then now() + interval '10 minutes' else locked_until end
     where id = a.id;
    return json_build_object('error', 'Wrong username or password.');
  end if;
  update accounts set failed_logins = 0, locked_until = null where id = a.id;
  return json_build_object('token', huss_new_session(a.id), 'username', a.username, 'account_id', a.id);
end $$;

-- ---------- load progress ----------
create or replace function public.huss_load(p_token text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare acc uuid := huss_account_for(p_token); a accounts%rowtype;
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
  select * into a from accounts where id = acc;
  return json_build_object('username', a.username, 'account_id', a.id, 'save', a.save,
                           'nick', (select nick from scores where id = a.id));
end $$;

-- ---------- save progress + update the leaderboard row ----------
create or replace function public.huss_store(
  p_token text, p_save jsonb, p_nick text,
  p_total double precision, p_hps double precision, p_jabs bigint, p_streak integer, p_prestige integer
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  acc uuid := huss_account_for(p_token);
  uname text;
  clean_nick text := left(btrim(regexp_replace(coalesce(p_nick, ''), '\s+', ' ', 'g')), 24);
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
  if p_save is not null and octet_length(p_save::text) > 50000 then
    return json_build_object('error', 'save too large');
  end if;
  if p_total is null or p_total = 'NaN' or p_total < 0 or p_total >= 1e40 then
    return json_build_object('error', 'bad score');
  end if;
  select username into uname from accounts where id = acc;
  update accounts set save = coalesce(p_save, save), save_updated_at = now() where id = acc;
  insert into scores (id, nick, total, hps, jabs, best_streak, prestige, is_account, updated_at)
  values (acc, coalesce(nullif(clean_nick, ''), uname), p_total,
          least(greatest(coalesce(nullif(p_hps, 'NaN'), 0), 0), 1e39),
          greatest(coalesce(p_jabs, 0), 0), greatest(coalesce(p_streak, 0), 0),
          greatest(coalesce(p_prestige, 0), 0), true, now())
  on conflict (id) do update
     set nick = excluded.nick, total = excluded.total, hps = excluded.hps, jabs = excluded.jabs,
         best_streak = excluded.best_streak, prestige = excluded.prestige, is_account = true, updated_at = now();
  return json_build_object('ok', true);
end $$;

-- ---------- log out ----------
create or replace function public.huss_logout(p_token text) returns void
language sql security definer set search_path = public, extensions as $$
  delete from sessions where token_hash = sha256(convert_to(coalesce(p_token, ''), 'UTF8'));
$$;

-- ---------- a guest who makes an account: drop their old guest row ----------
create or replace function public.huss_forget_guest(p_id uuid, p_secret text) returns void
language sql security definer set search_path = public, extensions as $$
  delete from scores s using score_secrets ss
   where s.id = p_id and ss.id = p_id
     and ss.secret_hash = sha256(convert_to(coalesce(p_secret, ''), 'UTF8'));
$$;

-- ---------- guest scores, now with belts ----------
drop function if exists public.submit_score(uuid, text, text, double precision, double precision, bigint, integer);
create or replace function public.submit_score(
  p_id uuid, p_secret text, p_nick text,
  p_total double precision, p_hps double precision, p_jabs bigint, p_streak integer,
  p_prestige integer default 0
) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  h bytea;
  existing bytea;
  clean_nick text := left(btrim(regexp_replace(coalesce(p_nick, ''), '\s+', ' ', 'g')), 24);
begin
  if p_id is null or p_secret is null or char_length(p_secret) < 20 then
    raise exception 'bad request';
  end if;
  if exists (select 1 from accounts where id = p_id) then
    raise exception 'not your score';
  end if;
  h := sha256(convert_to(p_secret, 'UTF8'));
  select secret_hash into existing from score_secrets where id = p_id;
  if existing is null then
    insert into scores (id, nick, total, hps, jabs, best_streak, prestige)
    values (p_id, clean_nick, greatest(p_total, 0), greatest(p_hps, 0), greatest(p_jabs, 0),
            greatest(p_streak, 0), greatest(coalesce(p_prestige, 0), 0));
    insert into score_secrets (id, secret_hash) values (p_id, h);
  elsif existing = h then
    update scores
       set nick = clean_nick, total = greatest(p_total, 0), hps = greatest(p_hps, 0),
           jabs = greatest(p_jabs, 0), best_streak = greatest(p_streak, 0),
           prestige = greatest(coalesce(p_prestige, 0), 0), updated_at = now()
     where id = p_id;
  else
    raise exception 'not your score';
  end if;
end $$;

-- ---------- who may call what ----------
revoke all on function public.huss_signup(text, text) from public;
revoke all on function public.huss_login(text, text) from public;
revoke all on function public.huss_load(text) from public;
revoke all on function public.huss_store(text, jsonb, text, double precision, double precision, bigint, integer, integer) from public;
revoke all on function public.huss_logout(text) from public;
revoke all on function public.huss_forget_guest(uuid, text) from public;
revoke all on function public.submit_score(uuid, text, text, double precision, double precision, bigint, integer, integer) from public;

grant execute on function public.huss_signup(text, text) to anon, authenticated;
grant execute on function public.huss_login(text, text) to anon, authenticated;
grant execute on function public.huss_load(text) to anon, authenticated;
grant execute on function public.huss_store(text, jsonb, text, double precision, double precision, bigint, integer, integer) to anon, authenticated;
grant execute on function public.huss_logout(text) to anon, authenticated;
grant execute on function public.huss_forget_guest(uuid, text) to anon, authenticated;
grant execute on function public.submit_score(uuid, text, text, double precision, double precision, bigint, integer, integer) to anon, authenticated;

-- Manual password reset for a friend (run in the SQL Editor, change both values):
--   update public.accounts set password_hash = extensions.crypt('their-new-password', extensions.gen_salt('bf', 10))
--    where lower(username) = lower('TheirUsername');
