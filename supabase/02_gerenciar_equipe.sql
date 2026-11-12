-- =================================================================
-- RegistroFácil — o admin gerencia a equipe pelo próprio app
-- (criar vendedor, trocar senha de alguém, remover acesso)
-- Todas as funções recusam quem não é admin.
-- =================================================================

create or replace function public.admin_criar_usuario(p_usuario text, p_nome text, p_senha text, p_papel text default 'vendedor')
returns void language plpgsql security definer set search_path = '' as $$
declare uid uuid := gen_random_uuid(); em text; u text := lower(trim(p_usuario));
begin
  if not public.eh_admin() then raise exception 'Somente o administrador pode criar usuários'; end if;
  if u !~ '^[a-z0-9._-]{2,30}$' then raise exception 'Usuário inválido: use só letras minúsculas, números, ponto ou traço (sem espaço e sem acento)'; end if;
  if coalesce(trim(p_nome),'') = '' then raise exception 'Informe o nome do vendedor'; end if;
  if length(coalesce(p_senha,'')) < 6 then raise exception 'A senha precisa ter pelo menos 6 caracteres'; end if;
  if p_papel not in ('admin','vendedor') then raise exception 'Tipo de acesso inválido'; end if;
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

create or replace function public.admin_trocar_senha(p_usuario text, p_senha text)
returns void language plpgsql security definer set search_path = '' as $$
declare uid uuid;
begin
  if not public.eh_admin() then raise exception 'Somente o administrador pode trocar senhas'; end if;
  if length(coalesce(p_senha,'')) < 6 then raise exception 'A senha precisa ter pelo menos 6 caracteres'; end if;
  select id into uid from public.perfis where usuario = lower(trim(p_usuario));
  if uid is null then raise exception 'Usuário não encontrado'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_senha, extensions.gen_salt('bf')), updated_at = now() where id = uid;
  delete from auth.sessions where user_id = uid;   -- desconecta os aparelhos com a senha antiga
end $$;

create or replace function public.admin_remover_usuario(p_usuario text)
returns void language plpgsql security definer set search_path = '' as $$
declare uid uuid;
begin
  if not public.eh_admin() then raise exception 'Somente o administrador pode remover usuários'; end if;
  select id into uid from public.perfis where usuario = lower(trim(p_usuario));
  if uid is null then raise exception 'Usuário não encontrado'; end if;
  if uid = auth.uid() then raise exception 'Você não pode remover o seu próprio acesso'; end if;
  delete from auth.users where id = uid;   -- os fretes que ele lançou continuam (só perdem o vínculo)
end $$;

revoke execute on function public.admin_criar_usuario(text,text,text,text), public.admin_trocar_senha(text,text), public.admin_remover_usuario(text) from public, anon;
grant  execute on function public.admin_criar_usuario(text,text,text,text), public.admin_trocar_senha(text,text), public.admin_remover_usuario(text) to authenticated;
