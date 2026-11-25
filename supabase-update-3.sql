-- Huss Huss Huss, update 3: "online now" leaderboard + ring chat.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to run again.

-- ---------- Online now ----------
-- Every open game tab checks in about every 20 seconds (that refreshes scores.updated_at).
-- "Online" = checked in within the last 45 seconds, measured on the server's clock.
create or replace view public.online_scores with (security_invoker = true) as
  select id, nick, total, hps, prestige, updated_at
    from public.scores
   where updated_at > now() - interval '45 seconds';
grant select on public.online_scores to anon, authenticated;

-- ---------- Ring chat ----------
-- Everyone can read. Only logged-in players can post, through huss_chat().
-- To remove a message: Table Editor → chat_messages → delete the row.
-- To ban someone: Table Editor → accounts → delete their account.
create table if not exists public.chat_messages (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  author_id  uuid not null,
  nick       text not null check (char_length(nick) between 1 and 24),
  body       text not null check (char_length(body) between 1 and 200)
);
create index if not exists chat_messages_author_time on public.chat_messages (author_id, created_at desc);

alter table public.chat_messages enable row level security;
drop policy if exists "Anyone can read chat" on public.chat_messages;
create policy "Anyone can read chat" on public.chat_messages for select to anon, authenticated using (true);
grant select on public.chat_messages to anon, authenticated;
revoke insert, update, delete on public.chat_messages from anon, authenticated;

create or replace function public.huss_chat(p_token text, p_body text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  acc uuid := huss_account_for(p_token);
  n text;
  b text;
begin
  if acc is null then return json_build_object('error', 'session expired'); end if;
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
  -- keep only the newest 500 messages
  delete from chat_messages where id <= (select max(id) - 500 from chat_messages);
  return json_build_object('ok', true);
end $$;

revoke all on function public.huss_chat(text, text) from public;
grant execute on function public.huss_chat(text, text) to anon, authenticated;
