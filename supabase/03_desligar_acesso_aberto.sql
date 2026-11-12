-- =================================================================
-- RegistroFácil — DESLIGA o acesso aberto (senha única antiga)
-- Rodar no MESMO momento em que a versão com login for publicada:
-- a partir daqui, só quem entra com usuário e senha vê/lança fretes.
-- =================================================================

drop policy if exists acesso_total on public.fretes;

-- quem não fez login não lê, não lança, não edita e não apaga nada
revoke all on public.fretes from anon;
revoke all on public.perfis from anon;
revoke all on public.fretes_backup_nomes_20260923 from anon, authenticated;
