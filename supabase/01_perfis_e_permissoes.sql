-- =================================================================
-- RegistroFácil — login individual e permissões por perfil
-- Parte 1 (aditiva): não muda nada para a versão antiga do app.
-- =================================================================

-- Perfis: quem é quem e o que pode ver
create table if not exists public.perfis (
  id      uuid primary key references auth.users(id) on delete cascade,
  usuario text not null unique,                 -- nome usado no login (ex.: lagoa)
  nome    text not null,                        -- nome do vendedor nos fretes (ex.: Lagoa)
  papel   text not null check (papel in ('admin','vendedor'))
);
alter table public.perfis enable row level security;

-- Funções auxiliares (security definer para não cair em recursão de RLS)
create or replace function public.eh_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.perfis where id = auth.uid() and papel = 'admin');
$$;

create or replace function public.eh_vendedor() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.perfis where id = auth.uid() and papel = 'vendedor');
$$;

create or replace function public.meu_nome() returns text
language sql stable security definer set search_path = '' as $$
  select nome from public.perfis where id = auth.uid();
$$;

-- Lista de nomes de lojas (sem valores) para as sugestões do formulário
create or replace function public.lojas_cadastradas() returns setof text
language sql stable security definer set search_path = '' as $$
  select distinct loja from public.fretes
  where (public.eh_admin() or public.eh_vendedor()) and loja is not null
  order by loja;
$$;

revoke execute on function public.eh_admin(), public.eh_vendedor(), public.meu_nome(), public.lojas_cadastradas() from public, anon;
grant  execute on function public.eh_admin(), public.eh_vendedor(), public.meu_nome(), public.lojas_cadastradas() to authenticated;

drop policy if exists perfis_leitura on public.perfis;
create policy perfis_leitura on public.perfis for select to authenticated
  using (id = auth.uid() or public.eh_admin());

-- Quem lançou cada frete (preenchido automaticamente no login)
alter table public.fretes
  add column if not exists criado_por uuid default auth.uid() references auth.users(id) on delete set null;
create index if not exists fretes_criado_por_idx on public.fretes (criado_por);

-- Políticas novas (passam a valer sozinhas quando a parte 2 remover "acesso_total")
drop policy if exists admin_tudo on public.fretes;
create policy admin_tudo on public.fretes for all to authenticated
  using (public.eh_admin()) with check (public.eh_admin());

drop policy if exists vendedor_insere on public.fretes;
create policy vendedor_insere on public.fretes for insert to authenticated
  with check (public.eh_vendedor() and criado_por = auth.uid() and vendedor = public.meu_nome());

-- Vendedor só enxerga/edita/exclui o que ELE lançou HOJE (horário de Brasília)
drop policy if exists vendedor_ve_hoje on public.fretes;
create policy vendedor_ve_hoje on public.fretes for select to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date);

drop policy if exists vendedor_edita_hoje on public.fretes;
create policy vendedor_edita_hoje on public.fretes for update to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date)
  with check (public.eh_vendedor() and criado_por = auth.uid() and vendedor = public.meu_nome());

drop policy if exists vendedor_exclui_hoje on public.fretes;
create policy vendedor_exclui_hoje on public.fretes for delete to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date);

-- Ninguém altera "quando" nem "quem" lançou: só os campos do frete
revoke update on public.fretes from anon, authenticated;
grant  update (vendedor, loja, valor, volume, data, obs) on public.fretes to anon, authenticated; -- anon sai na parte 2
