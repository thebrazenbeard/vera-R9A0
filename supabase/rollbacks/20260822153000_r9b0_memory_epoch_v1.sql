-- BT2 R9B0 memory epoch v1 safe-disable / forward-fix rollback.
-- Never drops tables, rows, events, receipts, or predecessor Vera data.

REVOKE ALL ON FUNCTION public.vera_memory_epoch_get_status_v1(text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_resume_incomplete_v1(text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_begin_revalidation_v1(uuid,text,text,uuid,text,text,bigint,uuid,text,text,text,text,text,bigint,text,text,text,jsonb,uuid) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_admission_v1(uuid,text,bigint,uuid,text,boolean,text,text,text,bigint,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_write_supabase_replica_v1(uuid,text,bigint,uuid,text,text,bytea,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_archive_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,timestamptz,text,uuid,uuid,uuid,text,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_finalize_v1(uuid,text,bigint,uuid,text,uuid,uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON TABLE
  public.vera_memory_epoch_subjects_v1,
  public.vera_memory_epoch_events_v1,
  public.vera_memory_epoch_provider_receipts_v1,
  public.vera_memory_epoch_archive_receipts_v1
FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON SEQUENCE public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq
FROM PUBLIC, anon, authenticated, service_role;

-- Existing evidence is intentionally preserved. Any correction is a reviewed successor migration.

REVOKE ALL ON FUNCTION public._vera_memory_epoch_guard_v1() FROM PUBLIC, anon, authenticated, service_role;
