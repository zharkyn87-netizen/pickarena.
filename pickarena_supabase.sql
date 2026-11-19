-- PickArena: Supabase schema (run in SQL Editor as project owner)
create table if not exists public.pickarena_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9._-]{3,24}$'),
  display_name text not null,
  role text not null default 'player' check (role in ('player','admin')),
  league text default 'B',
  created_at timestamptz not null default now()
);

create table if not exists public.pickarena_state (
  id integer primary key check (id = 1),
  data jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.pickarena_predictions (
  player_id uuid not null references public.pickarena_profiles(id) on delete cascade,
  round_number integer not null,
  predictions jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (player_id, round_number)
);

alter table public.pickarena_profiles enable row level security;
alter table public.pickarena_state enable row level security;
alter table public.pickarena_predictions enable row level security;

-- Profiles are private to their owner; public player details are shown in the shared tournament JSON.
drop policy if exists "profile read own" on public.pickarena_profiles;
create policy "profile read own" on public.pickarena_profiles for select to authenticated using (id = auth.uid());
drop policy if exists "state read authenticated" on public.pickarena_state;
create policy "state read authenticated" on public.pickarena_state for select to authenticated using (true);
drop policy if exists "state insert admin" on public.pickarena_state;
create policy "state insert admin" on public.pickarena_state for insert to authenticated with check (exists (select 1 from public.pickarena_profiles p where p.id = auth.uid() and p.role = 'admin'));
drop policy if exists "state update admin" on public.pickarena_state;
create policy "state update admin" on public.pickarena_state for update to authenticated using (exists (select 1 from public.pickarena_profiles p where p.id = auth.uid() and p.role = 'admin')) with check (exists (select 1 from public.pickarena_profiles p where p.id = auth.uid() and p.role = 'admin'));
drop policy if exists "predictions read authenticated" on public.pickarena_predictions;
create policy "predictions read authenticated" on public.pickarena_predictions for select to authenticated using (true);

-- Username registration: the browser first creates a Supabase Auth account, then calls this function.
create or replace function public.pickarena_register_player(p_username text, p_display_name text, p_league text)
returns void language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
begin
  if uid is null then raise exception 'Authentication required'; end if;
  if p_username !~ '^[a-z0-9._-]{3,24}$' then raise exception 'Invalid username'; end if;
  if length(trim(p_display_name)) < 2 then raise exception 'Display name is too short'; end if;
  insert into public.pickarena_profiles(id, username, display_name, role, league)
  values(uid, lower(p_username), trim(p_display_name), 'player', p_league);
  if exists (select 1 from public.pickarena_state where id = 1) then
    update public.pickarena_state
       set data = jsonb_set(data, '{players}', coalesce(data->'players','[]'::jsonb) || jsonb_build_array(
         jsonb_build_object('id', uid::text, 'name', trim(p_display_name), 'login', lower(p_username), 'league', p_league,
           'favoriteClub', 'Не указан', 'bio', 'Новый участник турнира', 'avatar', '', 'awards', '[]'::jsonb, 'isConfirmed', false)
       )), updated_at = now()
     where id = 1;
  end if;
end; $$;
revoke all on function public.pickarena_register_player(text,text,text) from public;
grant execute on function public.pickarena_register_player(text,text,text) to authenticated;

-- Players can only save predictions attached to their own authenticated account.
create or replace function public.pickarena_save_predictions(p_round_number integer, p_predictions jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  round_start text;
begin
  if uid is null then raise exception 'Authentication required'; end if;
  if not exists (select 1 from public.pickarena_profiles where id = uid and role = 'player') then raise exception 'Player account required'; end if;
  select r->>'startTime' into round_start
    from public.pickarena_state s, jsonb_array_elements(s.data->'rounds') r
   where s.id = 1 and (r->>'number')::integer = p_round_number;
  if round_start is null then raise exception 'Round not found'; end if;
  if (round_start::timestamp at time zone 'Asia/Almaty') <= now() + interval '5 minutes' then raise exception 'Prediction deadline has passed'; end if;
  insert into public.pickarena_predictions(player_id, round_number, predictions, updated_at)
  values(uid, p_round_number, coalesce(p_predictions, '{}'::jsonb), now())
  on conflict (player_id, round_number) do update set predictions = excluded.predictions, updated_at = now();
end; $$;
revoke all on function public.pickarena_save_predictions(integer,jsonb) from public;
grant execute on function public.pickarena_save_predictions(integer,jsonb) to authenticated;

-- Create the first administrator manually in Supabase Auth (email: admin@pickarena.invalid),
-- then run this statement after replacing the email if you chose another admin username:
-- insert into public.pickarena_profiles(id, username, display_name, role, league)
-- select id, 'admin', 'Администратор', 'admin', 'A' from auth.users where email = 'admin@pickarena.invalid'
-- on conflict (id) do update set role='admin';
