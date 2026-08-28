-- BT2 R9B0 memory epoch v1 disposable/transactional SQL acceptance test.
-- Must be run only in an isolated disposable database/branch after applying the candidate migration.
-- Caller MUST pre-set: SET bt2.r9b0_disposable_test_db = 'YES';

BEGIN;

DO $guard$
BEGIN
  IF pg_catalog.current_setting('bt2.r9b0_disposable_test_db', true) IS DISTINCT FROM 'YES' THEN
    RAISE EXCEPTION 'REFUSING_R9B0_EPOCH_TEST_OUTSIDE_EXPLICIT_DISPOSABLE_CONTEXT';
  END IF;
END
$guard$ LANGUAGE plpgsql;

DO $meta$
DECLARE
  n_api int;
  r record;
BEGIN
  IF pg_catalog.to_regclass('public.vera_memory_epoch_subjects_v1') IS NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_events_v1') IS NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_provider_receipts_v1') IS NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_archive_receipts_v1') IS NULL THEN
    RAISE EXCEPTION 'TEST_FAIL: expected four epoch tables';
  END IF;

  SELECT count(*) INTO n_api
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public'
    AND p.proname IN (
      'vera_memory_epoch_get_status_v1','vera_memory_epoch_resume_incomplete_v1',
      'vera_memory_epoch_begin_revalidation_v1','vera_memory_epoch_record_admission_v1',
      'vera_memory_epoch_write_supabase_replica_v1','vera_memory_epoch_record_provider_readback_v1',
      'vera_memory_epoch_record_archive_readback_v1','vera_memory_epoch_finalize_v1'
    );
  IF n_api <> 8 THEN RAISE EXCEPTION 'TEST_FAIL: expected 8 epoch RPCs, got %',n_api; END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname='vera_memory_epoch_resolve_conflict_v1'
  ) THEN
    RAISE EXCEPTION 'TEST_FAIL: unreviewed conflict resolver must be absent';
  END IF;

  FOR r IN
    SELECT c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN (
      'vera_memory_epoch_subjects_v1','vera_memory_epoch_events_v1',
      'vera_memory_epoch_provider_receipts_v1','vera_memory_epoch_archive_receipts_v1'
    )
  LOOP
    IF NOT r.relrowsecurity OR NOT r.relforcerowsecurity THEN
      RAISE EXCEPTION 'TEST_FAIL: RLS/FORCE missing on %',r.relname;
    END IF;
    IF pg_catalog.has_table_privilege('anon',r.oid,'SELECT')
       OR pg_catalog.has_table_privilege('authenticated',r.oid,'SELECT')
       OR pg_catalog.has_table_privilege('service_role',r.oid,'SELECT')
       OR pg_catalog.has_table_privilege('anon',r.oid,'INSERT')
       OR pg_catalog.has_table_privilege('authenticated',r.oid,'INSERT')
       OR pg_catalog.has_table_privilege('service_role',r.oid,'INSERT')
       OR pg_catalog.has_table_privilege('anon',r.oid,'UPDATE')
       OR pg_catalog.has_table_privilege('authenticated',r.oid,'UPDATE')
       OR pg_catalog.has_table_privilege('service_role',r.oid,'UPDATE')
       OR pg_catalog.has_table_privilege('anon',r.oid,'DELETE')
       OR pg_catalog.has_table_privilege('authenticated',r.oid,'DELETE')
       OR pg_catalog.has_table_privilege('service_role',r.oid,'DELETE') THEN
      RAISE EXCEPTION 'TEST_FAIL: non-owner raw table privilege on %',r.relname;
    END IF;
  END LOOP;

  IF pg_catalog.to_regclass('public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq') IS NULL THEN
    RAISE EXCEPTION 'TEST_FAIL: provider observation ordinal identity sequence absent';
  END IF;

  IF (
    SELECT pg_catalog.pg_get_userbyid(c.relowner)
    FROM pg_catalog.pg_class c
    WHERE c.oid=pg_catalog.to_regclass('public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq')
  ) <> 'postgres' THEN
    RAISE EXCEPTION 'TEST_FAIL: provider observation ordinal identity sequence owner is not postgres';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(c.relacl,pg_catalog.acldefault('S',c.relowner))
    ) acl
    WHERE c.oid=pg_catalog.to_regclass('public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq')
      AND acl.grantee=0
  ) THEN
    RAISE EXCEPTION 'TEST_FAIL: PUBLIC sequence privilege leaked on provider observation ordinal identity sequence';
  END IF;

  FOR r IN SELECT rolname FROM pg_catalog.pg_roles WHERE rolname IN ('anon','authenticated','service_role') LOOP
    IF pg_catalog.has_sequence_privilege(r.rolname,'public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq','SELECT')
       OR pg_catalog.has_sequence_privilege(r.rolname,'public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq','USAGE')
       OR pg_catalog.has_sequence_privilege(r.rolname,'public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq','UPDATE') THEN
      RAISE EXCEPTION 'TEST_FAIL: effective sequence privilege leaked to % on provider observation ordinal identity sequence',r.rolname;
    END IF;
  END LOOP;

  FOR r IN
    SELECT p.oid,p.proname,p.prosecdef,p.proconfig
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname LIKE 'vera_memory_epoch_%_v1'
      AND p.proname <> '_vera_memory_epoch_guard_v1'
  LOOP
    IF NOT r.prosecdef THEN RAISE EXCEPTION 'TEST_FAIL: API % must be SECURITY DEFINER',r.proname; END IF;
    IF (SELECT pg_catalog.pg_get_userbyid(p2.proowner) FROM pg_catalog.pg_proc p2 WHERE p2.oid=r.oid) <> 'postgres' THEN
      RAISE EXCEPTION 'TEST_FAIL: API % owner is not postgres',r.proname;
    END IF;
    IF NOT (r.proconfig @> ARRAY['search_path=pg_catalog']::text[]) THEN
      RAISE EXCEPTION 'TEST_FAIL: API % lacks pinned pg_catalog search_path',r.proname;
    END IF;
    IF pg_catalog.has_function_privilege('anon',r.oid,'EXECUTE')
       OR pg_catalog.has_function_privilege('authenticated',r.oid,'EXECUTE')
       OR pg_catalog.has_function_privilege('service_role',r.oid,'EXECUTE') THEN
      RAISE EXCEPTION 'TEST_FAIL: non-owner EXECUTE leaked on %',r.proname;
    END IF;
  END LOOP;

  IF pg_catalog.has_function_privilege('anon','public._vera_memory_epoch_guard_v1()','EXECUTE')
     OR pg_catalog.has_function_privilege('authenticated','public._vera_memory_epoch_guard_v1()','EXECUTE')
     OR pg_catalog.has_function_privilege('service_role','public._vera_memory_epoch_guard_v1()','EXECUTE') THEN
    RAISE EXCEPTION 'TEST_FAIL: internal guard EXECUTE leaked';
  END IF;

  IF pg_catalog.to_regclass('public.bt2_r9b0_disposable_347d_fixture_v1') IS NULL THEN
    RAISE EXCEPTION 'TEST_FAIL: disposable 347D predecessor marker table absent';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.bt2_r9b0_disposable_347d_fixture_v1
    WHERE fixture_generation = 'BT2_R9B0_DISPOSABLE_347D_PREDECESSOR_V1'
  ) THEN
    RAISE EXCEPTION 'TEST_FAIL: disposable 347D predecessor generation marker absent';
  END IF;

  FOR r IN
    WITH fixture AS (
      SELECT *
      FROM public.bt2_r9b0_disposable_347d_fixture_v1
      WHERE fixture_generation = 'BT2_R9B0_DISPOSABLE_347D_PREDECESSOR_V1'
    )
    SELECT * FROM (
      SELECT 'vera_verified_datum_heads_v2'::text AS relname,
             fixture.vera_verified_datum_heads_v2_oid AS expected_local_oid,
             'b770cf0f95df711b423d597ee3580f24fb5035e54a1e64b39cfce75c0ba39528'::text AS expected_sha
      FROM fixture
      UNION ALL
      SELECT 'vera_active_datum_index_v2', fixture.vera_active_datum_index_v2_oid,
             '13ee4b7dbd686249694df5d776ab4bf1794b76c2dc60b25a674ca2b440541e06'
      FROM fixture
      UNION ALL
      SELECT 'vera_inactive_datum_archive_v2', fixture.vera_inactive_datum_archive_v2_oid,
             '86903e04d351e8e4c96bb852f5a561ba8a6280b044d702914869ab8e3622cc31'
      FROM fixture
      UNION ALL
      SELECT 'vera_current_context_v3', fixture.vera_current_context_v3_oid,
             '161ddc031254f878893e5ed1e176d04ed5fa673f0ac7bc63054584f4bd053c59'
      FROM fixture
    ) x
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public'
        AND c.relname=r.relname
        AND c.relkind='v'
        AND c.oid=r.expected_local_oid
        AND pg_catalog.pg_get_userbyid(c.relowner)='postgres'
        AND c.reloptions=ARRAY['security_invoker=true']::text[]
        AND pg_catalog.encode(extensions.digest(pg_catalog.pg_get_viewdef(c.oid,true),'sha256'),'hex')=r.expected_sha
        AND c.relacl IS NOT NULL
        AND pg_catalog.cardinality(c.relacl)=2
        AND pg_catalog.aclcontains(c.relacl,'postgres=arwdDxtm/postgres'::aclitem)
        AND pg_catalog.aclcontains(c.relacl,'service_role=r/postgres'::aclitem)
        AND NOT pg_catalog.has_table_privilege('anon',c.oid,'SELECT')
        AND NOT pg_catalog.has_table_privilege('authenticated',c.oid,'SELECT')
        AND pg_catalog.has_table_privilege('service_role',c.oid,'SELECT')
        AND NOT pg_catalog.has_table_privilege('service_role',c.oid,'INSERT')
        AND NOT pg_catalog.has_table_privilege('service_role',c.oid,'UPDATE')
        AND NOT pg_catalog.has_table_privilege('service_role',c.oid,'DELETE')
    ) THEN
      RAISE EXCEPTION 'TEST_FAIL: portable 347D semantic/local-OID noninterference regression on %',r.relname;
    END IF;
  END LOOP;
END
$meta$ LANGUAGE plpgsql;

DO $flow$
DECLARE
  sid constant uuid := '70000000-0000-4000-8000-000000000001';
  mid constant uuid := '70000000-0000-4000-8000-000000000002';
  attempt constant uuid := '70000000-0000-4000-8000-000000000003';
  begin_e constant uuid := '70000000-0000-4000-8000-000000000004';
  admission_e constant uuid := '70000000-0000-4000-8000-000000000005';
  write_e constant uuid := '70000000-0000-4000-8000-000000000006';
  sup_receipt constant uuid := '70000000-0000-4000-8000-000000000007';
  sup_e constant uuid := '70000000-0000-4000-8000-000000000008';
  drive_receipt constant uuid := '70000000-0000-4000-8000-000000000009';
  drive_e constant uuid := '70000000-0000-4000-8000-00000000000a';
  sup_absent_receipt constant uuid := '70000000-0000-4000-8000-000000000020';
  sup_absent_e constant uuid := '70000000-0000-4000-8000-000000000021';
  sup_receipt_2 constant uuid := '70000000-0000-4000-8000-000000000022';
  sup_e_2 constant uuid := '70000000-0000-4000-8000-000000000023';
  archive_stale constant uuid := '70000000-0000-4000-8000-000000000026';
  archive_stale_e constant uuid := '70000000-0000-4000-8000-000000000027';
  sup_post_archive_bad constant uuid := '70000000-0000-4000-8000-000000000028';
  sup_post_archive_bad_e constant uuid := '70000000-0000-4000-8000-000000000029';
  sup_post_archive_fresh constant uuid := '70000000-0000-4000-8000-00000000002a';
  sup_post_archive_fresh_e constant uuid := '70000000-0000-4000-8000-00000000002b';
  archive_final constant uuid := '70000000-0000-4000-8000-00000000002d';
  archive_final_e constant uuid := '70000000-0000-4000-8000-00000000002e';
  archive_locator_bad constant uuid := '70000000-0000-4000-8000-000000000033';
  archive_locator_bad_e constant uuid := '70000000-0000-4000-8000-000000000034';
  archive_forged constant uuid := '70000000-0000-4000-8000-000000000035';
  forged_finalize_e constant uuid := '70000000-0000-4000-8000-000000000036';
  archive_amb constant uuid := '70000000-0000-4000-8000-00000000000b';
  archive_amb_e constant uuid := '70000000-0000-4000-8000-00000000000c';
  drive_receipt_2 constant uuid := '70000000-0000-4000-8000-00000000000d';
  drive_e_2 constant uuid := '70000000-0000-4000-8000-00000000000e';
  drive_receipt_3 constant uuid := '70000000-0000-4000-8000-000000000024';
  drive_e_3 constant uuid := '70000000-0000-4000-8000-000000000025';
  archive_ok constant uuid := '70000000-0000-4000-8000-00000000000f';
  archive_ok_e constant uuid := '70000000-0000-4000-8000-000000000010';
  final_e constant uuid := '70000000-0000-4000-8000-000000000011';
  original bytea := pg_catalog.convert_to('ORIGINAL PRE-R9B0 TEST BYTES','UTF8');
  envelope bytea := pg_catalog.convert_to('{"schema":"MemoryEpochEnvelopeV1","provenance":{"retrieval_time":null,"limitations":["RETRIEVAL_TIME_UNKNOWN"]},"fixture":"R9B0"}','UTF8');
  original_sha text;
  envelope_sha text;
  admission_sha text;
  provenance_sha text;
  container_sha text;
  empty_sha text;
  j jsonb;
  pre_context_count bigint;
  pre_save_count bigint;
BEGIN
  original_sha := pg_catalog.encode(extensions.digest(original,'sha256'),'hex');
  envelope_sha := pg_catalog.encode(extensions.digest(envelope,'sha256'),'hex');
  admission_sha := pg_catalog.encode(extensions.digest('ADMISSION-METADATA','sha256'),'hex');
  provenance_sha := pg_catalog.encode(extensions.digest('ORIGINAL-PROVENANCE','sha256'),'hex');
  container_sha := pg_catalog.encode(extensions.digest('IMMUTABLE-ARCHIVE-CONTAINER','sha256'),'hex');
  empty_sha := pg_catalog.encode(extensions.digest(''::text,'sha256'),'hex');

  SELECT count(*) INTO pre_context_count FROM public.vera_context_events_v3;
  SELECT count(*) INTO pre_save_count FROM public.vera_save_state_events;

  j := public.vera_memory_epoch_get_status_v1('bt2-test','branch-test',mid,'R9B0');
  IF j->>'state' <> 'UNVERIFIED_PRE_R9B0' OR (j->>'exists')::boolean THEN
    RAISE EXCEPTION 'TEST_FAIL: absent status is not virtual UNVERIFIED_PRE_R9B0';
  END IF;
  IF EXISTS (SELECT 1 FROM public.vera_memory_epoch_subjects_v1 WHERE logical_memory_id=mid) THEN
    RAISE EXCEPTION 'TEST_FAIL: get_status mutated state';
  END IF;
  j := public.vera_memory_epoch_resume_incomplete_v1('bt2-test','branch-test',mid,'R9B0');
  IF EXISTS (SELECT 1 FROM public.vera_memory_epoch_subjects_v1 WHERE logical_memory_id=mid) THEN
    RAISE EXCEPTION 'TEST_FAIL: resume_incomplete mutated state';
  END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'APPLIED' OR j->>'state'<>'REVALIDATING_R9B0' OR (j->>'state_version')::bigint<>1 THEN
    RAISE EXCEPTION 'TEST_FAIL: begin_revalidation %',j;
  END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: begin replay %',j; END IF;

  j := public.vera_memory_epoch_record_admission_v1(
    sid,'REVALIDATING_R9B0',1,attempt,'op-admit',true,'admission-gen-1',admission_sha,envelope_sha,
    pg_catalog.octet_length(envelope),admission_e,pg_catalog.jsonb_build_object('source_as_data',true));
  IF j->>'status'<>'APPLIED' OR j->>'state'<>'ADMISSION_VERIFIED' OR (j->>'state_version')::bigint<>2 THEN
    RAISE EXCEPTION 'TEST_FAIL: admission %',j;
  END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-illegal-finalize','70000000-0000-4000-8000-000000000099',
    admission_e,drive_receipt,sup_receipt,archive_ok,pg_catalog.jsonb_build_object('must_fail',true));
  IF j->>'status'<>'CAS_CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: finalize skipped evidence %',j; END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-sup-write',envelope_sha,envelope,write_e,
    pg_catalog.jsonb_build_object('resource_profile','MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT_TEST'));
  IF j->>'status'<>'APPLIED' OR j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>3 THEN
    RAISE EXCEPTION 'TEST_FAIL: supabase write %',j;
  END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-sup-write',envelope_sha,envelope,write_e,'{}'::jsonb);
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: exact write replay %',j; END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-write',
    pg_catalog.encode(extensions.digest('CHANGED'::text,'sha256'),'hex'),pg_catalog.convert_to('CHANGED','UTF8'),
    '70000000-0000-4000-8000-000000000098','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: changed bytes under same op not conflict %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT',pg_catalog.jsonb_build_object('timestamp_is_provenance_only',true));
  IF j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>4 THEN RAISE EXCEPTION 'TEST_FAIL: one-sided sup receipt %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    drive_receipt,sid,'MIGRATION_INCOMPLETE',4,attempt,'op-drive-read',drive_e,
    'GOOGLE_DRIVE_DURABLE','drive-test-root','drive-file-test','rev-1',
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:02-04:00','2026-08-22T12:00:03-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'DRIVE_EXACT_DOWNLOAD','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>5 THEN RAISE EXCEPTION 'TEST_FAIL: dual receipt convergence %',j; END IF;

  -- A later ABSENT observation for Supabase invalidates the old exact receipt as the current binding.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_absent_receipt,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',5,attempt,'op-sup-absent',sup_absent_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2026-08-22T12:00:04-04:00',
    0,empty_sha,'SUPABASE_DIRECT_READ','ABSENT',pg_catalog.jsonb_build_object('observed','NO_PROVIDER_BYTES'));
  IF j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>6 THEN RAISE EXCEPTION 'TEST_FAIL: later absent receipt must demote pending state %',j; END IF;

  -- Hostile currentness: caller-provided future time on the older exact receipt must not outrank the later DB observation.
  IF NOT EXISTS (
    SELECT 1
    FROM public.vera_memory_epoch_provider_receipts_v1 old_r
    JOIN public.vera_memory_epoch_provider_receipts_v1 new_r ON new_r.receipt_id=sup_absent_receipt
    WHERE old_r.receipt_id=sup_receipt
      AND old_r.readback_time > new_r.readback_time
      AND old_r.observation_ordinal < new_r.observation_ordinal
  ) THEN RAISE EXCEPTION 'TEST_FAIL: DB monotonic observation ordering not established'; END IF;

  -- Re-reading Drive alone must NOT reestablish dual pending while the latest Supabase binding is ABSENT.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    drive_receipt_2,sid,'MIGRATION_INCOMPLETE',6,attempt,'op-drive-reread-currentness',drive_e_2,
    'GOOGLE_DRIVE_DURABLE','drive-test-root','drive-file-test','rev-1',
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:02-04:00','2026-08-22T12:00:05-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'DRIVE_EXACT_DOWNLOAD','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>7 THEN RAISE EXCEPTION 'TEST_FAIL: stale old Supabase exact receipt incorrectly counted as current %',j; END IF;

  -- Fresh Supabase exact readback restores two current exact bindings.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt_2,sid,'MIGRATION_INCOMPLETE',7,attempt,'op-sup-reread-exact',sup_e_2,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2026-08-22T12:00:06-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>8 THEN RAISE EXCEPTION 'TEST_FAIL: current dual exact receipts did not restore pending archive %',j; END IF;

  -- The stale original Supabase exact receipt carries a future external timestamp, but must be rejected by DB observation order.
  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_stale,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',8,attempt,'op-archive-stale-provider',archive_stale_e,
    'legacy://fixture','archive-bundle-stale','gen-stale',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2026-08-22T12:00:06-04:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_2,sup_receipt,'VERIFIED_EXACT',pg_catalog.jsonb_build_object('must_fail_stale_provider',true));
  IF j->>'status'<>'CAS_CONFLICT' OR j->>'reason'<>'ARCHIVE_REQUIRES_CURRENT_PROVIDER_RECEIPTS' THEN
    RAISE EXCEPTION 'TEST_FAIL: stale future-timestamp exact receipt archived %',j;
  END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_amb,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',8,attempt,'op-archive-ambiguous',archive_amb_e,
    'legacy://fixture','archive-bundle-test','gen-1',NULL,'memories/test/original.bin','gzip',NULL,NULL,NULL,
    '2026-08-22T12:00:07-04:00','ARCHIVE_INSPECTOR',admission_e,drive_receipt_2,sup_receipt_2,'AMBIGUOUS',
    pg_catalog.jsonb_build_object('effect_outcome','OUTCOME_UNKNOWN'));
  IF j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>9 THEN RAISE EXCEPTION 'TEST_FAIL: V5 archive ambiguity recovery %',j; END IF;

  -- Recovery re-verifies a provider after inspecting the preserved exact effects.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    drive_receipt_3,sid,'MIGRATION_INCOMPLETE',9,attempt,'op-drive-reread-after-archive',drive_e_3,
    'GOOGLE_DRIVE_DURABLE','drive-test-root','drive-file-test','rev-1',
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:02-04:00','2026-08-22T12:00:08-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'DRIVE_EXACT_DOWNLOAD','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>10 THEN RAISE EXCEPTION 'TEST_FAIL: recovery did not reestablish pending archive %',j; END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_ok,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',10,attempt,'op-archive-exact',archive_ok_e,
    'legacy://fixture','archive-bundle-test','gen-2',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2026-08-22T12:00:09-04:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_receipt_2,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>11 THEN RAISE EXCEPTION 'TEST_FAIL: exact archive receipt should remain pending until finalize %',j; END IF;

  -- A later adverse provider observation after archive invalidates the provider receipt that archive_ok bound.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_post_archive_bad,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',11,attempt,'op-sup-post-archive-error',sup_post_archive_bad_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2025-01-01T00:00:00-05:00',
    0,empty_sha,'SUPABASE_DIRECT_READ','ERROR',pg_catalog.jsonb_build_object('hostile','later_db_observation_earlier_external_time'));
  IF j->>'state'<>'MIGRATION_INCOMPLETE' OR (j->>'state_version')::bigint<>12 THEN RAISE EXCEPTION 'TEST_FAIL: post-archive adverse observation did not invalidate pending %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_post_archive_fresh,sid,'MIGRATION_INCOMPLETE',12,attempt,'op-sup-post-archive-fresh',sup_post_archive_fresh_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2024-01-01T00:00:00-05:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>13 THEN RAISE EXCEPTION 'TEST_FAIL: fresh post-archive exact did not restore pending %',j; END IF;

  -- Finalization with the archive-bound but now stale Supabase receipt must fail on trusted observation order.
  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-finalize-stale-provider','70000000-0000-4000-8000-00000000002c',
    admission_e,drive_receipt_3,sup_receipt_2,archive_ok,pg_catalog.jsonb_build_object('must_fail_stale_provider',true));
  IF j->>'status'<>'CAS_CONFLICT' OR j->>'reason'<>'STALE_PROVIDER_RECEIPT_SELECTION' THEN
    RAISE EXCEPTION 'TEST_FAIL: stale provider receipt finalized %',j;
  END IF;

  -- DB-G5 provenance hostile: caller archive locator must equal the frozen subject locator.
  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_locator_bad,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-locator-mismatch',archive_locator_bad_e,
    'legacy://FORGED-LOCATOR','archive-bundle-test','gen-locator-hostile',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' OR j->>'reason'<>'ARCHIVE_SOURCE_LOCATOR_MISMATCH' THEN
    RAISE EXCEPTION 'TEST_FAIL: archive source locator mismatch not rejected %',j;
  END IF;
  IF (SELECT state_version FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=sid) <> 13
     OR EXISTS (SELECT 1 FROM public.vera_memory_epoch_archive_receipts_v1 WHERE archive_receipt_id=archive_locator_bad)
     OR EXISTS (SELECT 1 FROM public.vera_memory_epoch_events_v1 WHERE event_id=archive_locator_bad_e) THEN
    RAISE EXCEPTION 'TEST_FAIL: archive source locator mismatch caused mutation';
  END IF;

  -- Defense-in-depth hostile: even owner-injected exact-byte archive evidence with a forged locator cannot finalize.
  INSERT INTO public.vera_memory_epoch_archive_receipts_v1(
    archive_receipt_id,subject_id,attempt_id,project_id,branch_id,logical_memory_id,epoch_id,
    original_source_locator,original_sha256,original_byte_length,original_provenance_digest,
    archive_bundle_id,archive_generation,archive_container_sha256,archive_entry_path,compression_method,
    archive_member_sha256,extracted_readback_byte_length,extracted_readback_sha256,readback_time,verifier_identity,
    admission_receipt_id,drive_receipt_id,supabase_receipt_id,operation_id,result,limitations
  ) VALUES (
    archive_forged,sid,attempt,'bt2-test','branch-test',mid,'R9B0',
    'legacy://FORGED-LOCATOR',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'archive-bundle-forged','gen-forged',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','OWNER_LEVEL_HOSTILE_FIXTURE',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'op-forged-archive-direct','VERIFIED_EXACT','{}'::jsonb
  );
  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-finalize-forged-locator',forged_finalize_e,
    admission_e,drive_receipt_3,sup_post_archive_fresh,archive_forged,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' OR j->>'reason'<>'FINALIZATION_EVIDENCE_NOT_EXACT' THEN
    RAISE EXCEPTION 'TEST_FAIL: forged archive source locator finalized %',j;
  END IF;
  IF (SELECT state_version FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=sid) <> 13
     OR EXISTS (SELECT 1 FROM public.vera_memory_epoch_events_v1 WHERE event_id=forged_finalize_e) THEN
    RAISE EXCEPTION 'TEST_FAIL: forged archive locator finalization caused mutation';
  END IF;

  -- Re-archive against the current provider receipts after the adverse/fresh sequence.
  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-3',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'state'<>'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' OR (j->>'state_version')::bigint<>14 THEN RAISE EXCEPTION 'TEST_FAIL: current-provider rearchive %',j; END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    admission_e,drive_receipt_3,sup_post_archive_fresh,archive_final,pg_catalog.jsonb_build_object('currentness_separate',true));
  IF j->>'status'<>'APPLIED' OR j->>'state'<>'R9B0_VERIFIED_ACTIVE' OR (j->>'state_version')::bigint<>15 OR (j->>'present_truth_promoted')::boolean THEN
    RAISE EXCEPTION 'TEST_FAIL: finalization %',j;
  END IF;

  j := public.vera_memory_epoch_get_status_v1('bt2-test','branch-test',mid,'R9B0');
  IF j->>'state'<>'R9B0_VERIFIED_ACTIVE' OR (j->>'present_truth_promoted')::boolean THEN
    RAISE EXCEPTION 'TEST_FAIL: active status truth ceiling %',j;
  END IF;

  IF (SELECT count(*) FROM public.vera_context_events_v3) <> pre_context_count
     OR (SELECT count(*) FROM public.vera_save_state_events) <> pre_save_count THEN
    RAISE EXCEPTION 'TEST_FAIL: predecessor row mutation';
  END IF;

  -- Direct identity mutation must fail even as owner; trigger enforces immutable subject binding.
  BEGIN
    UPDATE public.vera_memory_epoch_subjects_v1 SET project_id='tampered-project' WHERE subject_id=sid;
    RAISE EXCEPTION 'TEST_FAIL: immutable subject update unexpectedly succeeded';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM='TEST_FAIL: immutable subject update unexpectedly succeeded' THEN RAISE; END IF;
  END;

  -- Append-only evidence must reject UPDATE and DELETE.
  BEGIN
    UPDATE public.vera_memory_epoch_events_v1 SET event_payload='{}'::jsonb WHERE event_id=begin_e;
    RAISE EXCEPTION 'TEST_FAIL: event update unexpectedly succeeded';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM='TEST_FAIL: event update unexpectedly succeeded' THEN RAISE; END IF;
  END;
  BEGIN
    DELETE FROM public.vera_memory_epoch_provider_receipts_v1 WHERE receipt_id=sup_receipt;
    RAISE EXCEPTION 'TEST_FAIL: provider receipt delete unexpectedly succeeded';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM='TEST_FAIL: provider receipt delete unexpectedly succeeded' THEN RAISE; END IF;
  END;

  IF (SELECT count(*) FROM public.vera_memory_epoch_events_v1 WHERE subject_id=sid) <> 12 THEN
    RAISE EXCEPTION 'TEST_FAIL: expected 12 monotonic evidence events';
  END IF;
END
$flow$ LANGUAGE plpgsql;


-- Hostile stable-operation replay matrix. These calls run after the main flow reached ACTIVE.
-- Replay lookup occurs before state/CAS eligibility checks, so this cleanly proves operation-id binding.
-- p_event_payload and p_limitations are intentionally diagnostic-only/non-binding; changing only those must still REPLAY.
DO $replay_matrix$
DECLARE
  sid constant uuid := '70000000-0000-4000-8000-000000000001';
  mid constant uuid := '70000000-0000-4000-8000-000000000002';
  attempt constant uuid := '70000000-0000-4000-8000-000000000003';
  begin_e constant uuid := '70000000-0000-4000-8000-000000000004';
  admission_e constant uuid := '70000000-0000-4000-8000-000000000005';
  write_e constant uuid := '70000000-0000-4000-8000-000000000006';
  sup_receipt constant uuid := '70000000-0000-4000-8000-000000000007';
  sup_e constant uuid := '70000000-0000-4000-8000-000000000008';
  drive_receipt_3 constant uuid := '70000000-0000-4000-8000-000000000024';
  sup_post_archive_fresh constant uuid := '70000000-0000-4000-8000-00000000002a';
  archive_final constant uuid := '70000000-0000-4000-8000-00000000002d';
  archive_final_e constant uuid := '70000000-0000-4000-8000-00000000002e';
  final_e constant uuid := '70000000-0000-4000-8000-000000000011';
  original bytea := pg_catalog.convert_to('ORIGINAL PRE-R9B0 TEST BYTES','UTF8');
  envelope bytea := pg_catalog.convert_to('{"schema":"MemoryEpochEnvelopeV1","provenance":{"retrieval_time":null,"limitations":["RETRIEVAL_TIME_UNKNOWN"]},"fixture":"R9B0"}','UTF8');
  original_sha text;
  envelope_sha text;
  admission_sha text;
  provenance_sha text;
  container_sha text;
  changed_sha text;
  j jsonb;
  v_before bigint;
BEGIN
  original_sha := pg_catalog.encode(extensions.digest(original,'sha256'),'hex');
  envelope_sha := pg_catalog.encode(extensions.digest(envelope,'sha256'),'hex');
  admission_sha := pg_catalog.encode(extensions.digest('ADMISSION-METADATA','sha256'),'hex');
  provenance_sha := pg_catalog.encode(extensions.digest('ORIGINAL-PROVENANCE','sha256'),'hex');
  container_sha := pg_catalog.encode(extensions.digest('IMMUTABLE-ARCHIVE-CONTAINER','sha256'),'hex');
  changed_sha := pg_catalog.encode(extensions.digest('CHANGED-MATERIAL-BINDING','sha256'),'hex');
  SELECT state_version INTO v_before FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=sid;
  IF v_before <> 15 THEN RAISE EXCEPTION 'TEST_FAIL: replay matrix expected final state_version 15, got %',v_before; END IF;

  -- BEGIN: exact retry replays. Each omitted V2 binding now independently conflicts.
  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: replay matrix begin exact %',j; END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'CHANGED_SOURCE_PROVIDER','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: begin source_provider rebound %',j; END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),changed_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: begin provenance rebound %',j; END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'CHANGED_PRIVACY','ACTIVE',pg_catalog.jsonb_build_object('rule','CLAIM_SPECIFIC_CURRENTNESS'),begin_e);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: begin privacy rebound %',j; END IF;

  j := public.vera_memory_epoch_begin_revalidation_v1(
    sid,'bt2-test','branch-test',mid,'R9B0','UNVERIFIED_PRE_R9B0',0,attempt,'op-begin',
    'LEGACY_SOURCE','legacy://fixture','source-gen-1',original_sha,pg_catalog.octet_length(original),provenance_sha,
    'PRIVATE_PROJECT','ACTIVE',pg_catalog.jsonb_build_object('rule','CHANGED_CURRENTNESS'),begin_e);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: begin currentness rebound %',j; END IF;

  -- ADMISSION: diagnostic payload may change; admission generation/metadata/envelope length may not.
  j := public.vera_memory_epoch_record_admission_v1(
    sid,'REVALIDATING_R9B0',1,attempt,'op-admit',true,'admission-gen-1',admission_sha,envelope_sha,
    pg_catalog.octet_length(envelope),admission_e,pg_catalog.jsonb_build_object('diagnostic_changed_on_retry',true));
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: admission diagnostic-only retry %',j; END IF;

  j := public.vera_memory_epoch_record_admission_v1(
    sid,'REVALIDATING_R9B0',1,attempt,'op-admit',true,'admission-gen-CHANGED',admission_sha,envelope_sha,
    pg_catalog.octet_length(envelope),admission_e,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: admission generation rebound %',j; END IF;

  j := public.vera_memory_epoch_record_admission_v1(
    sid,'REVALIDATING_R9B0',1,attempt,'op-admit',true,'admission-gen-1',changed_sha,envelope_sha,
    pg_catalog.octet_length(envelope),admission_e,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: admission metadata rebound %',j; END IF;

  j := public.vera_memory_epoch_record_admission_v1(
    sid,'REVALIDATING_R9B0',1,attempt,'op-admit',true,'admission-gen-1',admission_sha,envelope_sha,
    pg_catalog.octet_length(envelope)+1,admission_e,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: admission envelope length rebound %',j; END IF;

  -- SUPABASE WRITE: diagnostic payload may change; predecessor/event/canonical bytes may not.
  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-sup-write',envelope_sha,envelope,write_e,
    pg_catalog.jsonb_build_object('diagnostic_changed_on_retry',true));
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: write diagnostic-only retry %',j; END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',999,attempt,'op-sup-write',envelope_sha,envelope,write_e,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: write predecessor rebound %',j; END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-sup-write',envelope_sha,envelope,
    '70000000-0000-4000-8000-000000000096','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: write event_id rebound %',j; END IF;

  j := public.vera_memory_epoch_write_supabase_replica_v1(
    sid,'ADMISSION_VERIFIED',2,attempt,'op-sup-write',changed_sha,pg_catalog.convert_to('CHANGED-MATERIAL-BINDING','UTF8'),write_e,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: write canonical bytes rebound %',j; END IF;

  -- PROVIDER READBACK: limitations are diagnostics; provider identity/locator/revision/verifier/time are material.
  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT',
    pg_catalog.jsonb_build_object('diagnostic_changed_on_retry',true));
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: provider diagnostic-only retry %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','CHANGED_PROVIDER_ID','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: provider identity rebound %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','CHANGED_LOCATOR',NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: provider locator rebound %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,'CHANGED_REV',
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: provider revision rebound %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2036-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'CHANGED_VERIFIER_ROUTE','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: provider verifier rebound %',j; END IF;

  j := public.vera_memory_epoch_record_provider_readback_v1(
    sup_receipt,sid,'MIGRATION_INCOMPLETE',3,attempt,'op-sup-read',sup_e,
    'SUPABASE_RUNTIME','klmbpaigzeguvnpccqzz','public.vera_memory_epoch_subjects_v1:'||sid::text,NULL,
    pg_catalog.octet_length(envelope),'2026-08-22T12:00:00-04:00','2037-08-22T12:00:01-04:00',
    pg_catalog.octet_length(envelope),envelope_sha,'SUPABASE_DIRECT_READ','VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: provider provenance time rebound %',j; END IF;

  -- ARCHIVE: limitations are diagnostics; generation/path/member/predecessor receipt identities are material.
  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-3',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT',pg_catalog.jsonb_build_object('diagnostic_changed_on_retry',true));
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: archive diagnostic-only retry %',j; END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-CHANGED',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: archive generation rebound %',j; END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-3',container_sha,'CHANGED/PATH.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: archive path rebound %',j; END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-3',container_sha,'memories/test/original.bin','gzip',
    changed_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,drive_receipt_3,sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: archive member rebound %',j; END IF;

  j := public.vera_memory_epoch_record_archive_readback_v1(
    archive_final,sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',13,attempt,'op-archive-final-current',archive_final_e,
    'legacy://fixture','archive-bundle-test','gen-3',container_sha,'memories/test/original.bin','gzip',
    original_sha,pg_catalog.octet_length(original),original_sha,'2023-01-01T00:00:00-05:00','ARCHIVE_EXTRACT_VERIFY',
    admission_e,'70000000-0000-4000-8000-000000000095',sup_post_archive_fresh,'VERIFIED_EXACT','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: archive predecessor receipt rebound %',j; END IF;

  -- FINALIZE: diagnostic payload may change; every selected evidence receipt ID is material.
  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    admission_e,drive_receipt_3,sup_post_archive_fresh,archive_final,pg_catalog.jsonb_build_object('diagnostic_changed_on_retry',true));
  IF j->>'status'<>'REPLAY' THEN RAISE EXCEPTION 'TEST_FAIL: finalize diagnostic-only retry %',j; END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    '70000000-0000-4000-8000-000000000094',drive_receipt_3,sup_post_archive_fresh,archive_final,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: finalize admission receipt rebound %',j; END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    admission_e,'70000000-0000-4000-8000-000000000093',sup_post_archive_fresh,archive_final,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: finalize drive receipt rebound %',j; END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    admission_e,drive_receipt_3,'70000000-0000-4000-8000-000000000092',archive_final,'{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: finalize supabase receipt rebound %',j; END IF;

  j := public.vera_memory_epoch_finalize_v1(
    sid,'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',14,attempt,'op-finalize',final_e,
    admission_e,drive_receipt_3,sup_post_archive_fresh,'70000000-0000-4000-8000-000000000091','{}'::jsonb);
  IF j->>'status'<>'CONFLICT' THEN RAISE EXCEPTION 'TEST_FAIL: finalize archive receipt rebound %',j; END IF;

  IF (SELECT state_version FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=sid) <> v_before THEN
    RAISE EXCEPTION 'TEST_FAIL: replay conflict matrix mutated state_version';
  END IF;
  IF (SELECT count(*) FROM public.vera_memory_epoch_events_v1 WHERE subject_id=sid) <> 12 THEN
    RAISE EXCEPTION 'TEST_FAIL: replay conflict matrix appended evidence';
  END IF;
END
$replay_matrix$ LANGUAGE plpgsql;

ROLLBACK;
