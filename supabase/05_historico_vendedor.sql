-- =================================================================
-- RegistroFácil — VENDEDOR passa a ter histórico
-- * Vê todos os fretes no nome dele (qualquer data, inclusive os que o
--   comprador lançou para ele e os antigos), com o valor de cada frete.
-- * Corrige/exclui os que ELE lançou (qualquer data) e os antigos no
--   nome dele. Os lançados pelo comprador ficam só para consulta.
-- (O app não mostra somas em R$ para o vendedor.)
-- =================================================================

drop policy if exists vendedor_ve_hoje on public.fretes;
drop policy if exists vendedor_edita_hoje on public.fretes;
drop policy if exists vendedor_exclui_hoje on public.fretes;

drop policy if exists vendedor_ve on public.fretes;
create policy vendedor_ve on public.fretes for select to authenticated
  using (public.eh_vendedor() and (vendedor = public.meu_nome() or criado_por = auth.uid()));

drop policy if exists vendedor_edita on public.fretes;
create policy vendedor_edita on public.fretes for update to authenticated
  using (public.eh_vendedor() and (criado_por = auth.uid() or (criado_por is null and vendedor = public.meu_nome())))
  with check (public.eh_vendedor() and (criado_por = auth.uid() or criado_por is null) and public.pode_lancar_como(vendedor));

drop policy if exists vendedor_exclui on public.fretes;
create policy vendedor_exclui on public.fretes for delete to authenticated
  using (public.eh_vendedor() and (criado_por = auth.uid() or (criado_por is null and vendedor = public.meu_nome())));
