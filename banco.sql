-- ============================================================
-- MV MODS — BANCO DE DADOS (1 arquivo só)
-- Como usar: Supabase > SQL Editor > New query > cole TUDO > Run.
-- Pode rodar mais de uma vez sem dar erro.
-- ============================================================

do $$ begin create type public.app_role as enum ('admin','user'); exception when duplicate_object then null; end $$;
do $$ begin create type public.content_category as enum ('jogo','skin','xite'); exception when duplicate_object then null; end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null, avatar_url text, blocked boolean not null default false,
  created_at timestamptz not null default now());
create table if not exists public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role app_role not null, unique(user_id, role));
create table if not exists public.contents (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null, name text not null, category content_category not null,
  description text not null default '', cover_url text, banner_url text,
  gallery text[] not null default '{}', current_version text not null default '1.0',
  status text not null default 'atualizado', published boolean not null default false,
  featured boolean not null default false, featured_title text, featured_description text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table if not exists public.versions (
  id uuid primary key default gen_random_uuid(),
  content_id uuid not null references public.contents(id) on delete cascade,
  version text not null, description text not null default '',
  features text[] not null default '{}', images text[] not null default '{}',
  is_current boolean not null default false, archived boolean not null default false,
  created_at timestamptz not null default now());
create table if not exists public.downloads (
  version_id uuid primary key references public.versions(id) on delete cascade, url text not null);
create table if not exists public.download_history (
  id uuid primary key default gen_random_uuid(), user_id uuid not null,
  content_id uuid not null references public.contents(id) on delete cascade,
  version text not null, created_at timestamptz not null default now());
create table if not exists public.favorites (
  user_id uuid not null, content_id uuid not null references public.contents(id) on delete cascade,
  created_at timestamptz not null default now(), primary key (user_id, content_id));
create table if not exists public.site_settings (
  id int primary key default 1 check (id=1),
  theme text not null default 'dark', primary_color text not null default 'roxo',
  button_style text not null default 'arredondado', card_size text not null default 'grande',
  hero_banner_url text, background_url text, sort_order text not null default 'recentes',
  hero_title text not null default 'SEU CATÁLOGO GAMER',
  hero_subtitle text not null default 'Encontre jogos, skins e conteúdos.');
insert into public.site_settings (id) values (1) on conflict do nothing;

create or replace function public.has_role(_user_id uuid, _role app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id=_user_id and role=_role) $$;
create or replace function public.is_active_user(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id=_user_id and blocked=false) $$;
create or replace function public.email_exists(_email text) returns boolean
language sql stable security definer set search_path = public, auth as $$
  select exists(select 1 from auth.users where lower(email)=lower(_email)) $$;
grant execute on function public.email_exists(text) to anon, authenticated;

-- Cria perfil e dá ADM automaticamente para o e-mail abaixo
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username) values (new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1))) on conflict do nothing;
  insert into public.user_roles (user_id, role) values (new.id, 'user') on conflict do nothing;
  if lower(new.email) = 'miguelccc360@gmail.com' then
    insert into public.user_roles (user_id, role) values (new.id, 'admin') on conflict do nothing;
  end if;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- Se a conta ADM já existir, libera agora
insert into public.user_roles (user_id, role)
select id, 'admin' from auth.users where lower(email)='miguelccc360@gmail.com' on conflict do nothing;

-- Permissões
grant select on public.profiles to anon, authenticated; grant update on public.profiles to authenticated;
grant select on public.user_roles to authenticated;
grant select on public.contents, public.versions, public.site_settings to anon;
grant select, insert, update, delete on public.contents, public.versions, public.downloads, public.download_history, public.favorites, public.site_settings to authenticated;
grant all on all tables in schema public to service_role;

alter table public.profiles enable row level security;
alter table public.user_roles enable row level security;
alter table public.contents enable row level security;
alter table public.versions enable row level security;
alter table public.downloads enable row level security;
alter table public.download_history enable row level security;
alter table public.favorites enable row level security;
alter table public.site_settings enable row level security;

do $$ declare r record; begin
  for r in select policyname, tablename from pg_policies where schemaname='public' loop
    execute format('drop policy if exists %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;

create policy "own profile or admin" on public.profiles for select to authenticated using (auth.uid()=id or has_role(auth.uid(),'admin'));
create policy "update own profile" on public.profiles for update to authenticated using (auth.uid()=id) with check (auth.uid()=id and blocked = (select p.blocked from public.profiles p where p.id=auth.uid()));
create policy "admin update profiles" on public.profiles for update to authenticated using (has_role(auth.uid(),'admin'));
create policy "read own roles" on public.user_roles for select to authenticated using (auth.uid()=user_id or has_role(auth.uid(),'admin'));
create policy "public published" on public.contents for select to anon, authenticated using (published or has_role(auth.uid(),'admin'));
create policy "admin all contents" on public.contents for all to authenticated using (has_role(auth.uid(),'admin')) with check (has_role(auth.uid(),'admin'));
create policy "public versions" on public.versions for select to anon, authenticated using (exists(select 1 from public.contents c where c.id=content_id and (c.published or has_role(auth.uid(),'admin'))));
create policy "admin all versions" on public.versions for all to authenticated using (has_role(auth.uid(),'admin')) with check (has_role(auth.uid(),'admin'));
create policy "active users read downloads" on public.downloads for select to authenticated using (
  has_role(auth.uid(),'admin') or (is_active_user(auth.uid()) and exists(select 1 from public.versions v join public.contents c on c.id=v.content_id where v.id=version_id and c.published and not v.archived)));
create policy "admin all downloads" on public.downloads for all to authenticated using (has_role(auth.uid(),'admin')) with check (has_role(auth.uid(),'admin'));
create policy "own history" on public.download_history for select to authenticated using (auth.uid()=user_id or has_role(auth.uid(),'admin'));
create policy "insert own history" on public.download_history for insert to authenticated with check (auth.uid()=user_id and is_active_user(auth.uid()));
create policy "own favorites" on public.favorites for all to authenticated using (auth.uid()=user_id) with check (auth.uid()=user_id);
create policy "public settings" on public.site_settings for select to anon, authenticated using (true);
create policy "admin settings" on public.site_settings for update to authenticated using (has_role(auth.uid(),'admin'));

-- Pasta de fotos (bucket "media")
insert into storage.buckets (id, name, public) values ('media','media',true)
on conflict (id) do update set public = true;
drop policy if exists "media read" on storage.objects;
drop policy if exists "media admin insert" on storage.objects;
drop policy if exists "media admin update" on storage.objects;
drop policy if exists "media admin delete" on storage.objects;
drop policy if exists "media avatar insert" on storage.objects;
create policy "media read" on storage.objects for select to anon, authenticated using (bucket_id='media');
create policy "media admin insert" on storage.objects for insert to authenticated with check (bucket_id='media' and public.has_role(auth.uid(),'admin'));
create policy "media avatar insert" on storage.objects for insert to authenticated with check (bucket_id='media' and (storage.foldername(name))[1]='avatars' and public.is_active_user(auth.uid()));
create policy "media admin update" on storage.objects for update to authenticated using (bucket_id='media' and public.has_role(auth.uid(),'admin'));
create policy "media admin delete" on storage.objects for delete to authenticated using (bucket_id='media' and public.has_role(auth.uid(),'admin'));

-- Sem verificação de e-mail: todo cadastro já nasce confirmado
create or replace function public.auto_confirm_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  new.email_confirmed_at := coalesce(new.email_confirmed_at, now());
  return new;
end $$;
drop trigger if exists auto_confirm_before_insert on auth.users;
create trigger auto_confirm_before_insert before insert on auth.users for each row execute function public.auto_confirm_user();
-- Confirma quem já tinha se cadastrado e ficou esperando
update auth.users set email_confirmed_at = now() where email_confirmed_at is null;
