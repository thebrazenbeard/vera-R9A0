-- R9B0 forward correction: provider-specific PROVIDER_READBACK event cardinality.
-- Preserves the in-flight R0 attempt and all existing rows. No provider effect occurs in this source migration itself.
DO $bt2_cardinality_pre$
DECLARE
  actual_constraint text;
  actual_function_hash text;
BEGIN
  SELECT pg_catalog.pg_get_constraintdef(c.oid,true)
    INTO actual_constraint
  FROM pg_catalog.pg_constraint c
  JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
  JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
  WHERE n.nspname='public' AND r.relname='vera_memory_epoch_events_v1'
    AND c.conname='vera_memory_epoch_event_operation_uq';
  IF actual_constraint IS DISTINCT FROM 'UNIQUE (subject_id, operation_id, event_kind)' THEN
    RAISE EXCEPTION 'BT2_CARDINALITY_PRESTATE_MISMATCH: old operation constraint changed: %',actual_constraint;
  END IF;

  SELECT pg_catalog.encode(extensions.digest(
           pg_catalog.convert_to(pg_catalog.pg_get_functiondef(
             'public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb)'::regprocedure
           ),'UTF8'),'sha256'),'hex')
    INTO actual_function_hash;
  IF actual_function_hash IS DISTINCT FROM 'f06a8849cf745248b2f26a810bf0eca812934c4c42545f76a6bf361a72750cff' THEN
    RAISE EXCEPTION 'BT2_CARDINALITY_PRESTATE_MISMATCH: provider-readback function hash changed: %',actual_function_hash;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_events_v1
    WHERE event_kind='PROVIDER_READBACK'
      AND ((event_payload->>'provider_class') IS NULL
           OR (event_payload->>'provider_class') NOT IN ('SUPABASE_RUNTIME','GOOGLE_DRIVE_DURABLE'))
  ) THEN
    RAISE EXCEPTION 'BT2_CARDINALITY_PRESTATE_MISMATCH: existing provider-readback event lacks allowed provider class';
  END IF;

  IF EXISTS (
    SELECT subject_id,operation_id,event_payload->>'provider_class'
    FROM public.vera_memory_epoch_events_v1
    WHERE event_kind='PROVIDER_READBACK'
    GROUP BY subject_id,operation_id,event_payload->>'provider_class'
    HAVING count(*)>1
  ) THEN
    RAISE EXCEPTION 'BT2_CARDINALITY_PRESTATE_MISMATCH: duplicate existing provider-specific event identity';
  END IF;
END
$bt2_cardinality_pre$ LANGUAGE plpgsql;

ALTER TABLE public.vera_memory_epoch_events_v1
  DROP CONSTRAINT vera_memory_epoch_event_operation_uq;

CREATE UNIQUE INDEX vera_memory_epoch_event_operation_nonprovider_uq
  ON public.vera_memory_epoch_events_v1(subject_id,operation_id,event_kind)
  WHERE event_kind <> 'PROVIDER_READBACK';

CREATE UNIQUE INDEX vera_memory_epoch_event_provider_operation_uq
  ON public.vera_memory_epoch_events_v1(subject_id,operation_id,((event_payload->>'provider_class')))
  WHERE event_kind='PROVIDER_READBACK';

ALTER TABLE public.vera_memory_epoch_events_v1
  ADD CONSTRAINT vera_memory_epoch_provider_event_class_ck CHECK (
    event_kind <> 'PROVIDER_READBACK'
    OR (
      (event_payload->>'provider_class') IS NOT NULL
      AND (event_payload->>'provider_class') IN ('SUPABASE_RUNTIME','GOOGLE_DRIVE_DURABLE')
    )
  );
CREATE OR REPLACE FUNCTION public.vera_memory_epoch_record_provider_readback_v1(
  p_receipt_id uuid,
  p_subject_id uuid,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_event_id uuid,
  p_provider_class text,
  p_provider_identity text,
  p_provider_locator text,
  p_provider_revision_or_version text,
  p_written_byte_length bigint,
  p_write_observation_time timestamptz,
  p_readback_time timestamptz,
  p_readback_byte_length bigint,
  p_readback_sha256 text,
  p_verifier_route text,
  p_result text,
  p_limitations jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  pr public.vera_memory_epoch_provider_receipts_v1%ROWTYPE;
  e public.vera_memory_epoch_events_v1%ROWTYPE;
  next_state text;
  next_version bigint;
  sup_exact boolean;
  drv_exact boolean;
  new_observation_ordinal bigint;
  replay_binding jsonb;
BEGIN
  replay_binding := pg_catalog.jsonb_build_object(
    'receipt_id',p_receipt_id,'subject_id',p_subject_id,'expected_prior_state',p_expected_prior_state,
    'expected_state_version',p_expected_state_version,'attempt_id',p_attempt_id,'operation_id',p_operation_id,
    'event_id',p_event_id,'provider_class',p_provider_class,'provider_identity',p_provider_identity,
    'provider_locator',p_provider_locator,'provider_revision_or_version',p_provider_revision_or_version,
    'written_byte_length',p_written_byte_length,'write_observation_time',p_write_observation_time,
    'readback_time',p_readback_time,'readback_byte_length',p_readback_byte_length,
    'readback_sha256',p_readback_sha256,'verifier_route',p_verifier_route,'result',p_result
  );
  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=p_subject_id FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUBJECT_ABSENT'); END IF;

  SELECT * INTO pr FROM public.vera_memory_epoch_provider_receipts_v1
  WHERE subject_id=p_subject_id AND provider_class=p_provider_class AND operation_id=p_operation_id;
  IF FOUND THEN
    SELECT * INTO e FROM public.vera_memory_epoch_events_v1
    WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='PROVIDER_READBACK'
      AND event_payload->>'provider_class'=p_provider_class;
    IF FOUND AND e.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','receipt_id',pr.receipt_id,'result',pr.result,'state',s.state,'state_version',s.state_version);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  SELECT * INTO e FROM public.vera_memory_epoch_events_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='PROVIDER_READBACK'
      AND event_payload->>'provider_class'=p_provider_class;
  IF FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','EVENT_OPERATION_COLLISION'); END IF;

  IF s.state <> p_expected_prior_state OR s.state_version <> p_expected_state_version OR s.current_attempt_id IS DISTINCT FROM p_attempt_id THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','state',s.state,'state_version',s.state_version);
  END IF;
  IF s.state IN ('R9B0_VERIFIED_ACTIVE','R9B0_ADMISSION_REJECTED','MIGRATION_CONFLICTED','REVALIDATING_R9B0','UNVERIFIED_PRE_R9B0') THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','PROVIDER_READBACK_NOT_ALLOWED_FROM_STATE','state',s.state);
  END IF;
  IF p_provider_class NOT IN ('SUPABASE_RUNTIME','GOOGLE_DRIVE_DURABLE') OR p_result NOT IN ('VERIFIED_EXACT','ABSENT','AMBIGUOUS','MISMATCH','ERROR') THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','INVALID_PROVIDER_OR_RESULT');
  END IF;
  IF s.envelope_sha256 IS NULL OR s.admission_metadata_sha256 IS NULL OR s.envelope_byte_length IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','ADMISSION_BINDING_INCOMPLETE');
  END IF;
  IF p_written_byte_length <> s.envelope_byte_length THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','WRITTEN_LENGTH_NOT_BOUND_ENVELOPE');
  END IF;
  IF p_provider_class='SUPABASE_RUNTIME' AND s.canonical_envelope IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','SUPABASE_RECEIPT_WITHOUT_SUPABASE_FULL_COPY');
  END IF;

  INSERT INTO public.vera_memory_epoch_provider_receipts_v1(
    receipt_id,subject_id,attempt_id,provider_class,provider_identity,provider_locator,provider_revision_or_version,
    operation_id,project_id,branch_id,logical_memory_id,epoch_id,original_sha256,admission_metadata_sha256,
    envelope_sha256,written_byte_length,write_observation_time,readback_time,readback_byte_length,readback_sha256,
    verifier_route,result,limitations
  ) VALUES (
    p_receipt_id,s.subject_id,p_attempt_id,p_provider_class,p_provider_identity,p_provider_locator,p_provider_revision_or_version,
    p_operation_id,s.project_id,s.branch_id,s.logical_memory_id,s.epoch_id,s.original_sha256,s.admission_metadata_sha256,
    s.envelope_sha256,p_written_byte_length,p_write_observation_time,p_readback_time,p_readback_byte_length,p_readback_sha256,
    p_verifier_route,p_result,p_limitations
  )
  RETURNING observation_ordinal INTO new_observation_ordinal;

  IF p_result='MISMATCH' THEN
    next_state := 'MIGRATION_CONFLICTED';
  ELSIF p_result IN ('ABSENT','AMBIGUOUS','ERROR') THEN
    next_state := 'MIGRATION_INCOMPLETE';
  ELSE
    SELECT COALESCE((
      SELECT x.result='VERIFIED_EXACT' AND x.envelope_sha256=s.envelope_sha256
      FROM public.vera_memory_epoch_provider_receipts_v1 x
      WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class='SUPABASE_RUNTIME'
      ORDER BY x.observation_ordinal DESC LIMIT 1
    ), false) INTO sup_exact;
    SELECT COALESCE((
      SELECT x.result='VERIFIED_EXACT' AND x.envelope_sha256=s.envelope_sha256
      FROM public.vera_memory_epoch_provider_receipts_v1 x
      WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class='GOOGLE_DRIVE_DURABLE'
      ORDER BY x.observation_ordinal DESC LIMIT 1
    ), false) INTO drv_exact;
    IF sup_exact AND drv_exact THEN next_state := 'DUAL_STORE_VERIFIED_PENDING_ARCHIVE';
    ELSE next_state := 'MIGRATION_INCOMPLETE'; END IF;
  END IF;

  next_version := s.state_version + 1;
  UPDATE public.vera_memory_epoch_subjects_v1
    SET state=next_state,state_version=next_version,updated_at=pg_catalog.clock_timestamp()
    WHERE subject_id=p_subject_id AND state_version=p_expected_state_version AND state=p_expected_prior_state;
  IF NOT FOUND THEN RAISE EXCEPTION 'BT2_INTERNAL_CAS_LOST_AFTER_RECEIPT_INSERT'; END IF;

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,next_version,p_expected_prior_state,next_state,p_attempt_id,p_operation_id,'PROVIDER_READBACK',
    p_expected_state_version,s.envelope_sha256,
    pg_catalog.jsonb_build_object(
      'provider_class',p_provider_class,'receipt_id',p_receipt_id,'result',p_result,
      'observation_ordinal',new_observation_ordinal,'readback_time_provenance',p_readback_time,
      'readback_sha256',p_readback_sha256,'readback_byte_length',p_readback_byte_length,
      'replay_binding',replay_binding,'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_limitations'),
      'incomplete_reasons',CASE WHEN next_state='MIGRATION_INCOMPLETE' THEN pg_catalog.jsonb_build_array('PROVIDER_READBACK_NOT_DUAL_EXACT') ELSE '[]'::jsonb END
    )
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','receipt_id',p_receipt_id,'event_id',p_event_id,'observation_ordinal',new_observation_ordinal,'state',next_state,'state_version',next_version,'result',p_result);
END
$fn$;

ALTER FUNCTION public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb) FROM PUBLIC, anon, authenticated, service_role;

COMMENT ON INDEX public.vera_memory_epoch_event_provider_operation_uq IS 'R9B0 provider-readback idempotency is per subject + logical operation + provider class.';