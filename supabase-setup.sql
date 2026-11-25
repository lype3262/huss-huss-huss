-- Huss Huss Huss leaderboard: run this once in Supabase → SQL Editor → New query → Run.
--
-- How it stays fair-ish without accounts:
--   * Anyone can READ the scores table.
--   * Nobody can write the table directly. Scores go through submit_score(),
--     which remembers a hashed secret per player (kept in that player's browser)
--     and refuses to overwrite a row unless the secret matches.
--   * To remove a cheater: Table Editor → scores → delete their row.

create table if not exists public.scores (
  id          uuid primary key,
  nick        text not null default '' check (char_length(nick) <= 24),
  total       double precision not null default 0 check (total >= 0 and total < 1e40),
  hps         double precision not null default 0 check (hps >= 0 and hps < 1e40),
  jabs        bigint not null default 0,
  best_streak integer not null default 0,
  updated_at  timestamptz not null default now()
);

create table if not exists public.score_secrets (
  id          uuid primary key references public.scores(id) on delete cascade,
  secret_hash bytea not null
);

-- Newer Supabase projects don't expose new tables automatically: let visitors read scores (only).
grant select on public.scores to anon, authenticated;

alter table public.scores        enable row level security;
alter table public.score_secrets enable row level security;

drop policy if exists "Anyone can read the leaderboard" on public.scores;
create policy "Anyone can read the leaderboard"
  on public.scores for select to anon, authenticated using (true);
-- score_secrets has no policies on purpose: the browser can never read or write it.

create or replace function public.submit_score(
  p_id uuid, p_secret text, p_nick text,
  p_total double precision, p_hps double precision, p_jabs bigint, p_streak integer
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  h bytea;
  existing bytea;
  clean_nick text := left(btrim(regexp_replace(coalesce(p_nick, ''), '\s+', ' ', 'g')), 24);
begin
  if p_id is null or p_secret is null or char_length(p_secret) < 20 then
    raise exception 'bad request';
  end if;
  h := sha256(convert_to(p_secret, 'UTF8'));

  select secret_hash into existing from score_secrets where id = p_id;

  if existing is null then
    insert into scores (id, nick, total, hps, jabs, best_streak)
    values (p_id, clean_nick, greatest(p_total, 0), greatest(p_hps, 0), greatest(p_jabs, 0), greatest(p_streak, 0));
    insert into score_secrets (id, secret_hash) values (p_id, h);
  elsif existing = h then
    update scores
       set nick = clean_nick, total = greatest(p_total, 0), hps = greatest(p_hps, 0),
           jabs = greatest(p_jabs, 0), best_streak = greatest(p_streak, 0), updated_at = now()
     where id = p_id;
  else
    raise exception 'not your score';
  end if;
end;
$$;

revoke all on function public.submit_score(uuid, text, text, double precision, double precision, bigint, integer) from public;
grant execute on function public.submit_score(uuid, text, text, double precision, double precision, bigint, integer) to anon, authenticated;
