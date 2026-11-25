-- Huss Huss Huss, update 4: force-reset and ban commands.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to run again.
--
-- ===================== HOW TO USE (run these in the SQL Editor) =====================
--   select huss_admin_reset('TheirUsername');       -- wipe their progress, on every device
--   select huss_admin_ban('TheirUsername');         -- ban the account and the name, remove their score and chat
--   select huss_admin_unban('TheirUsername');       -- undo a ban (their progress stays wiped)
--   select huss_admin_ban_guest('the-id-from-the-scores-table');   -- ban a guest (no username)
-- These commands only work from the SQL Editor. The website can't call them.
-- ====================================================================================
--
-- How a reset sticks: every account has a wipe_version. A reset bumps it. The game sends the
-- version its save belongs to whenever it saves; an older version is refused, and the game
-- then starts that player over from zero (within ~20 seconds if they're playing).

alter table public.accounts add column if not exists wipe_version integer not null default 0;
alter table public.accounts add column if not exists banned       boolean not null default false;

create table if not exists public.banned_names  (username_lower text primary key, banned_at timestamptz not null default now());
create table if not exists public.banned_guests (id uuid primary key,              banned_at timestamptz not null default now());
alter table public.banned_names  enable row level security;
alter table public.banned_guests enable row level security;
revoke all on public.banned_names  from anon, authenticated;
revoke all on public.banned_guests from anon, authenticated;

-- ---------- sign up: banned names can't be taken again ----------
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
  if exists (select 1 from banned_names where username_lower = lower(u)) then
    return json_build_object('error', 'That username isn''t available.');
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

-- ---------- log in: banned accounts are refused ----------
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
  if a.banned then
    return json_build_object('error', 'This account has been banned.');
  end if;
  update accounts set failed_logins = 0, locked_until = null where id = a.id;
  return json_build_object('token', huss_new_session(a.id), 'username', a.username, 'account_id', a.id);
end $$;

-- ---------- load: also reports bans and the current wipe version ----------
create or replace function public.huss_load(p_token text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare acc uuid := huss_account_for(p_token); a accounts%rowtype;
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
  select * into a from accounts where id = acc;
  if a.banned then return json_build_object('error', 'banned'); end if;
  return json_build_object('username', a.username, 'account_id', a.id, 'save', a.save,
                           'nick', (select nick from scores where id = a.id), 'wipe', a.wipe_version);
end $$;

-- ---------- store: refuses saves from before a reset, and banned accounts ----------
drop function if exists public.huss_store(text, jsonb, text, double precision, double precision, bigint, integer, integer);
create or replace function public.huss_store(
  p_token text, p_save jsonb, p_nick text,
  p_total double precision, p_hps double precision, p_jabs bigint, p_streak integer, p_prestige integer,
  p_wipe integer default 0
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  acc uuid := huss_account_for(p_token);
  uname text; is_banned boolean; wv integer;
  clean_nick text := left(btrim(regexp_replace(coalesce(p_nick, ''), '\s+', ' ', 'g')), 24);
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
  select username, banned, wipe_version into uname, is_banned, wv from accounts where id = acc;
  if is_banned then return json_build_object('error', 'banned'); end if;
  if coalesce(p_wipe, 0) < wv then return json_build_object('error', 'reset', 'wipe', wv); end if;
  if p_save is not null and octet_length(p_save::text) > 50000 then
    return json_build_object('error', 'save too large');
  end if;
  if p_total is null or p_total = 'NaN' or p_total < 0 or p_total >= 1e40 then
    return json_build_object('error', 'bad score');
  end if;
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

-- ---------- chat: banned accounts can't post ----------
create or replace function public.huss_chat(p_token text, p_body text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  acc uuid := huss_account_for(p_token);
  n text;
  b text;
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
  if exists (select 1 from accounts where id = acc and banned) then
    return json_build_object('error', 'banned');
  end if;
  b := regexp_replace(coalesce(p_body, ''), '[[:cntrl:]]', ' ', 'g');
  b := btrim(regexp_replace(b, '\s+', ' ', 'g'));
  if b = '' then return json_build_object('error', 'Type a message first.'); end if;
  if char_length(b) > 200 then return json_build_object('error', 'Messages can be at most 200 characters.'); end if;
  if exists (select 1 from chat_messages where author_id = acc and created_at > now() - interval '2 seconds') then
    return json_build_object('error', 'Slow down a little.');
  end if;
  if (select count(*) from chat_messages where author_id = acc and created_at > now() - interval '1 minute') >= 15 then
    return json_build_object('error', 'Too many messages. Wait a minute.');
  end if;
  select left(coalesce(nullif(s.nick, ''), a.username), 24) into n
    from accounts a left join scores s on s.id = a.id
   where a.id = acc;
  insert into chat_messages (author_id, nick, body) values (acc, n, b);
  delete from chat_messages where id <= (select max(id) - 500 from chat_messages);
  return json_build_object('ok', true);
end $$;

-- ---------- guest scores: banned guests are refused ----------
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
  if exists (select 1 from banned_guests where id = p_id) then
    raise exception 'banned';
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

-- ===================== admin commands (SQL Editor only) =====================
create or replace function public.huss_admin_reset(p_username text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare acc uuid; uname text;
begin
  select id, username into acc, uname from accounts where lower(username) = lower(btrim(coalesce(p_username, '')));
  if acc is null then return 'No account is called ' || coalesce(p_username, '(blank)') || '.'; end if;
  update accounts set save = null, save_updated_at = now(), wipe_version = wipe_version + 1 where id = acc;
  delete from scores where id = acc;
  return 'Reset ' || uname || '. Their game starts over from zero within about 20 seconds, on every device.';
end $$;

create or replace function public.huss_admin_ban(p_username text, p_delete_chat boolean default true) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare acc uuid; uname text := btrim(coalesce(p_username, ''));
begin
  if uname = '' then return 'Give a username.'; end if;
  insert into banned_names (username_lower) values (lower(uname)) on conflict do nothing;
  select id, username into acc, uname from accounts where lower(username) = lower(uname);
  if acc is null then
    return 'Nobody has that name yet, but ' || p_username || ' can no longer be signed up.';
  end if;
  update accounts set banned = true, save = null, save_updated_at = now(), wipe_version = wipe_version + 1 where id = acc;
  delete from scores where id = acc;
  if p_delete_chat then delete from chat_messages where author_id = acc; end if;
  return 'Banned ' || uname || '. They''re removed from the leaderboard'
         || case when p_delete_chat then ' and chat' else '' end
         || ', logged out within about 20 seconds, and the name can''t be signed up again.';
end $$;

create or replace function public.huss_admin_unban(p_username text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare n integer;
begin
  delete from banned_names where username_lower = lower(btrim(coalesce(p_username, '')));
  update accounts set banned = false where lower(username) = lower(btrim(coalesce(p_username, '')));
  get diagnostics n = row_count;
  return case when n > 0 then 'Unbanned ' || p_username || '. They can log in again (their progress stays wiped).'
              else 'Unblocked the name ' || p_username || ' (no account had it).' end;
end $$;

create or replace function public.huss_admin_ban_guest(p_id uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into banned_guests (id) values (p_id) on conflict do nothing;
  delete from scores where id = p_id;   -- also removes their stored secret
  return 'Banned that guest and removed their score. (They could still come back with a fresh browser.)';
end $$;

-- ---------- who may call what ----------
revoke all on function public.huss_admin_reset(text)              from public, anon, authenticated;
revoke all on function public.huss_admin_ban(text, boolean)        from public, anon, authenticated;
revoke all on function public.huss_admin_unban(text)               from public, anon, authenticated;
revoke all on function public.huss_admin_ban_guest(uuid)           from public, anon, authenticated;

revoke all on function public.huss_store(text, jsonb, text, double precision, double precision, bigint, integer, integer, integer) from public;
grant execute on function public.huss_store(text, jsonb, text, double precision, double precision, bigint, integer, integer, integer) to anon, authenticated;
grant execute on function public.huss_signup(text, text) to anon, authenticated;
grant execute on function public.huss_login(text, text)  to anon, authenticated;
grant execute on function public.huss_load(text)         to anon, authenticated;
grant execute on function public.huss_chat(text, text)   to anon, authenticated;
grant execute on function public.submit_score(uuid, text, text, double precision, double precision, bigint, integer, integer) to anon, authenticated;
