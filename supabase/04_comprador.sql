-- =================================================================
-- RegistroFácil — perfil COMPRADOR (ex.: Daniel)
-- * Lança fretes em nome de qualquer vendedor cadastrado.
-- * Vê, corrige e exclui os fretes que ELE lançou (qualquer data) e os
--   fretes antigos, de antes do login individual (sem autor registrado).
-- * Não vê os fretes lançados por outras pessoas depois do login novo.
-- (O app esconde dele os totais em R$, rankings e relatórios.)
-- =================================================================

alter table public.perfis drop constraint if exists perfis_papel_check;
alter table public.perfis add constraint perfis_papel_check check (papel in ('admin','vendedor','comprador'));

create or replace function public.eh_comprador() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.perfis where id = auth.uid() and papel = 'comprador');
$$;

-- nomes dos vendedores cadastrados (lista do formulário do comprador)
create or replace function public.nomes_vendedores() returns setof text
language sql stable security definer set search_path = '' as $$
  select nome from public.perfis
  where papel = 'vendedor' and (public.eh_admin() or public.eh_comprador())
  order by nome;
$$;

-- este usuário pode gravar um frete com este nome de vendedor?
create or replace function public.pode_lancar_como(p_vendedor text) returns boolean
language sql stable security definer set search_path = '' as $$
  select (public.eh_vendedor() and p_vendedor = public.meu_nome())
      or (public.eh_comprador() and exists (select 1 from public.perfis where papel = 'vendedor' and nome = p_vendedor));
$$;

create or replace function public.lojas_cadastradas() returns setof text
language sql stable security definer set search_path = '' as $$
  select distinct loja from public.fretes
  where (public.eh_admin() or public.eh_vendedor() or public.eh_comprador()) and loja is not null
  order by loja;
$$;

revoke execute on function public.eh_comprador(), public.nomes_vendedores(), public.pode_lancar_como(text) from public, anon;
grant  execute on function public.eh_comprador(), public.nomes_vendedores(), public.pode_lancar_como(text) to authenticated;

-- lançar: vendedor só no próprio nome; comprador em nome de vendedor cadastrado
drop policy if exists vendedor_insere on public.fretes;
create policy vendedor_insere on public.fretes for insert to authenticated
  with check (criado_por = auth.uid() and public.pode_lancar_como(vendedor));

-- VENDEDOR: só o que ele lançou HOJE (sem mudança de regra)
drop policy if exists vendedor_ve_hoje on public.fretes;
create policy vendedor_ve_hoje on public.fretes for select to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date);

drop policy if exists vendedor_edita_hoje on public.fretes;
create policy vendedor_edita_hoje on public.fretes for update to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date)
  with check (criado_por = auth.uid() and public.pode_lancar_como(vendedor));

drop policy if exists vendedor_exclui_hoje on public.fretes;
create policy vendedor_exclui_hoje on public.fretes for delete to authenticated
  using (public.eh_vendedor() and criado_por = auth.uid()
         and (created_at at time zone 'America/Sao_Paulo')::date = (now() at time zone 'America/Sao_Paulo')::date);

-- COMPRADOR: o que ele lançou (qualquer data) + fretes antigos sem autor
drop policy if exists comprador_ve on public.fretes;
create policy comprador_ve on public.fretes for select to authenticated
  using (public.eh_comprador() and (criado_por = auth.uid() or criado_por is null));

drop policy if exists comprador_edita on public.fretes;
create policy comprador_edita on public.fretes for update to authenticated
  using (public.eh_comprador() and (criado_por = auth.uid() or criado_por is null))
  with check (public.eh_comprador() and (criado_por = auth.uid() or criado_por is null) and public.pode_lancar_como(vendedor));

drop policy if exists comprador_exclui on public.fretes;
create policy comprador_exclui on public.fretes for delete to authenticated
  using (public.eh_comprador() and (criado_por = auth.uid() or criado_por is null));

-- o admin passa a poder criar compradores pelo painel Equipe
create or replace function public.admin_criar_usuario(p_usuario text, p_nome text, p_senha text, p_papel text default 'vendedor')
returns void language plpgsql security definer set search_path = '' as $$
declare uid uuid := gen_random_uuid(); em text; u text := lower(trim(p_usuario));
begin
  if not public.eh_admin() then raise exception 'Somente o administrador pode criar usuários'; end if;
  if u !~ '^[a-z0-9._-]{2,30}$' then raise exception 'Usuário inválido: use só letras minúsculas, números, ponto ou traço (sem espaço e sem acento)'; end if;
  if coalesce(trim(p_nome),'') = '' then raise exception 'Informe o nome'; end if;
  if length(coalesce(p_senha,'')) < 6 then raise exception 'A senha precisa ter pelo menos 6 caracteres'; end if;
  if p_papel not in ('admin','vendedor','comprador') then raise exception 'Tipo de acesso inválido'; end if;
  if exists (select 1 from public.perfis where usuario = u) then raise exception 'Já existe um usuário chamado %', u; end if;
  em := u || '@registrofacil.app';
  insert into auth.users (instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,
    raw_app_meta_data,raw_user_meta_data,created_at,updated_at,
    confirmation_token,recovery_token,email_change_token_new,email_change,email_change_token_current,
    phone_change,phone_change_token,reauthentication_token)
  values ('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',em,
    extensions.crypt(p_senha, extensions.gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}'::jsonb, jsonb_build_object('nome',trim(p_nome)), now(), now(),
    '','','','','','','','');
  insert into auth.identities (id,user_id,provider_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
  values (gen_random_uuid(),uid,uid::text,jsonb_build_object('sub',uid::text,'email',em,'email_verified',true),'email',now(),now(),now());
  insert into public.perfis (id,usuario,nome,papel) values (uid,u,trim(p_nome),p_papel);
end $$;

-- Daniel é comprador
update public.perfis set papel = 'comprador' where usuario = 'daniel';
