-- BT2 R9B0 memory epoch v1
-- Three exact migration candidate. READ/DESIGN artifact only until a separate current Supabase writer lease is issued.
-- Target: klmbpaigzeguvnpccqzz
-- Migration identity: 20260822153000_r9b0_memory_epoch_v1

-- Portable semantic preflight for the hardened 347D predecessor.
-- Provider-local OIDs and production migration-history identity are intentionally
-- NOT part of these portable bytes. They remain mandatory external D0 currentness
-- evidence immediately before any live Supabase effect.
DO $bt2_pre$
DECLARE
  r record;
  actual_oid oid;
  actual_hash text;
  actual_acl aclitem[];
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('vera_verified_datum_heads_v2'::text, 'b770cf0f95df711b423d597ee3580f24fb5035e54a1e64b39cfce75c0ba39528'::text),
      ('vera_active_datum_index_v2'::text, '13ee4b7dbd686249694df5d776ab4bf1794b76c2dc60b25a674ca2b440541e06'::text),
      ('vera_inactive_datum_archive_v2'::text, '86903e04d351e8e4c96bb852f5a561ba8a6280b044d702914869ab8e3622cc31'::text),
      ('vera_current_context_v3'::text, '161ddc031254f878893e5ed1e176d04ed5fa673f0ac7bc63054584f4bd053c59'::text)
    ) AS x(relname, expected_sha256)
  LOOP
    SELECT c.oid,
           pg_catalog.encode(extensions.digest(pg_catalog.pg_get_viewdef(c.oid, true), 'sha256'), 'hex'),
           c.relacl
      INTO actual_oid, actual_hash, actual_acl
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = r.relname
      AND c.relkind = 'v'
      AND pg_catalog.pg_get_userbyid(c.relowner) = 'postgres'
      AND c.reloptions = ARRAY['security_invoker=true']::text[];

    IF actual_oid IS NULL OR actual_hash IS DISTINCT FROM r.expected_sha256 THEN
      RAISE EXCEPTION 'BT2_PRESTATE_MISMATCH: hardened view % semantic identity changed', r.relname;
    END IF;

    IF actual_acl IS NULL
       OR pg_catalog.cardinality(actual_acl) <> 2
       OR NOT pg_catalog.aclcontains(actual_acl, 'postgres=arwdDxtm/postgres'::aclitem)
       OR NOT pg_catalog.aclcontains(actual_acl, 'service_role=r/postgres'::aclitem) THEN
      RAISE EXCEPTION 'BT2_PRESTATE_MISMATCH: exact hardened ACL posture changed on %', r.relname;
    END IF;

    IF pg_catalog.has_table_privilege('anon', actual_oid, 'SELECT')
       OR pg_catalog.has_table_privilege('authenticated', actual_oid, 'SELECT')
       OR pg_catalog.has_table_privilege('anon', actual_oid, 'INSERT')
       OR pg_catalog.has_table_privilege('authenticated', actual_oid, 'INSERT')
       OR pg_catalog.has_table_privilege('anon', actual_oid, 'UPDATE')
       OR pg_catalog.has_table_privilege('authenticated', actual_oid, 'UPDATE')
       OR pg_catalog.has_table_privilege('anon', actual_oid, 'DELETE')
       OR pg_catalog.has_table_privilege('authenticated', actual_oid, 'DELETE') THEN
      RAISE EXCEPTION 'BT2_PRESTATE_MISMATCH: anon/auth privilege regression on %', r.relname;
    END IF;

    IF NOT pg_catalog.has_table_privilege('service_role', actual_oid, 'SELECT')
       OR pg_catalog.has_table_privilege('service_role', actual_oid, 'INSERT')
       OR pg_catalog.has_table_privilege('service_role', actual_oid, 'UPDATE')
       OR pg_catalog.has_table_privilege('service_role', actual_oid, 'DELETE') THEN
      RAISE EXCEPTION 'BT2_PRESTATE_MISMATCH: service_role privilege drift on %', r.relname;
    END IF;
  END LOOP;

  IF pg_catalog.to_regclass('public.vera_memory_epoch_subjects_v1') IS NOT NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_events_v1') IS NOT NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_provider_receipts_v1') IS NOT NULL
     OR pg_catalog.to_regclass('public.vera_memory_epoch_archive_receipts_v1') IS NOT NULL THEN
    RAISE EXCEPTION 'BT2_PRESTATE_CONFLICT: one or more epoch relations already exist';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN (
        'vera_memory_epoch_get_status_v1',
        'vera_memory_epoch_resume_incomplete_v1',
        'vera_memory_epoch_begin_revalidation_v1',
        'vera_memory_epoch_record_admission_v1',
        'vera_memory_epoch_write_supabase_replica_v1',
        'vera_memory_epoch_record_provider_readback_v1',
        'vera_memory_epoch_record_archive_readback_v1',
        'vera_memory_epoch_finalize_v1',
        'vera_memory_epoch_resolve_conflict_v1',
        '_vera_memory_epoch_guard_v1'
      )
  ) THEN
    RAISE EXCEPTION 'BT2_PRESTATE_CONFLICT: epoch RPC namespace is not empty';
  END IF;
END
$bt2_pre$ LANGUAGE plpgsql;

CREATE TABLE public.vera_memory_epoch_subjects_v1 (
  subject_id uuid PRIMARY KEY,
  project_id text NOT NULL CHECK (project_id <> ''),
  branch_id text NOT NULL CHECK (branch_id <> ''),
  logical_memory_id uuid NOT NULL,
  epoch_id text NOT NULL CHECK (epoch_id = 'R9B0'),
  state text NOT NULL CHECK (state IN (
    'UNVERIFIED_PRE_R9B0',
    'REVALIDATING_R9B0',
    'ADMISSION_VERIFIED',
    'MIGRATION_INCOMPLETE',
    'MIGRATION_CONFLICTED',
    'DUAL_STORE_VERIFIED_PENDING_ARCHIVE',
    'R9B0_VERIFIED_ACTIVE',
    'R9B0_ADMISSION_REJECTED'
  )),
  state_version bigint NOT NULL CHECK (state_version >= 0),
  current_attempt_id uuid,
  source_provider text NOT NULL CHECK (source_provider <> ''),
  source_locator text NOT NULL CHECK (source_locator <> ''),
  source_version_or_generation text,
  original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
  original_byte_length bigint NOT NULL CHECK (original_byte_length >= 0),
  original_provenance_digest text NOT NULL CHECK (original_provenance_digest ~ '^[0-9a-f]{64}$'),
  admission_generation_or_digest text,
  admission_metadata_sha256 text CHECK (admission_metadata_sha256 IS NULL OR admission_metadata_sha256 ~ '^[0-9a-f]{64}$'),
  envelope_sha256 text CHECK (envelope_sha256 IS NULL OR envelope_sha256 ~ '^[0-9a-f]{64}$'),
  envelope_byte_length bigint CHECK (envelope_byte_length IS NULL OR envelope_byte_length > 0),
  canonical_envelope bytea,
  privacy_scope text NOT NULL CHECK (privacy_scope <> ''),
  lifecycle_status text NOT NULL CHECK (lifecycle_status <> ''),
  currentness_rule jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(currentness_rule) = 'object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  CONSTRAINT vera_memory_epoch_subject_identity_uq UNIQUE (project_id, branch_id, logical_memory_id, epoch_id),
  CONSTRAINT vera_memory_epoch_subject_crossbind_uq UNIQUE (subject_id, project_id, branch_id, logical_memory_id, epoch_id),
  CONSTRAINT vera_memory_epoch_envelope_complete_ck CHECK (
    (canonical_envelope IS NULL AND envelope_sha256 IS NULL AND envelope_byte_length IS NULL)
    OR
    (envelope_sha256 IS NOT NULL AND envelope_byte_length IS NOT NULL
      AND (canonical_envelope IS NULL OR (
        pg_catalog.octet_length(canonical_envelope) = envelope_byte_length
        AND pg_catalog.encode(extensions.digest(canonical_envelope, 'sha256'), 'hex') = envelope_sha256
      )))
  ),
  CONSTRAINT vera_memory_epoch_active_evidence_ck CHECK (
    state <> 'R9B0_VERIFIED_ACTIVE'
    OR (
      canonical_envelope IS NOT NULL
      AND envelope_sha256 IS NOT NULL
      AND envelope_byte_length IS NOT NULL
      AND admission_metadata_sha256 IS NOT NULL
      AND admission_generation_or_digest IS NOT NULL
    )
  ),
  CONSTRAINT vera_memory_epoch_rejected_no_active_copy_ck CHECK (
    state <> 'R9B0_ADMISSION_REJECTED' OR canonical_envelope IS NULL
  )
);

CREATE TABLE public.vera_memory_epoch_events_v1 (
  event_id uuid PRIMARY KEY,
  subject_id uuid NOT NULL REFERENCES public.vera_memory_epoch_subjects_v1(subject_id) ON DELETE RESTRICT,
  state_version bigint NOT NULL CHECK (state_version > 0),
  prior_state text CHECK (prior_state IS NULL OR prior_state IN (
    'UNVERIFIED_PRE_R9B0','REVALIDATING_R9B0','ADMISSION_VERIFIED','MIGRATION_INCOMPLETE',
    'MIGRATION_CONFLICTED','DUAL_STORE_VERIFIED_PENDING_ARCHIVE','R9B0_VERIFIED_ACTIVE','R9B0_ADMISSION_REJECTED'
  )),
  new_state text NOT NULL CHECK (new_state IN (
    'UNVERIFIED_PRE_R9B0','REVALIDATING_R9B0','ADMISSION_VERIFIED','MIGRATION_INCOMPLETE',
    'MIGRATION_CONFLICTED','DUAL_STORE_VERIFIED_PENDING_ARCHIVE','R9B0_VERIFIED_ACTIVE','R9B0_ADMISSION_REJECTED'
  )),
  attempt_id uuid NOT NULL,
  operation_id text NOT NULL CHECK (operation_id <> ''),
  event_kind text NOT NULL CHECK (event_kind IN (
    'BEGIN_REVALIDATION','ADMISSION','SUPABASE_REPLICA_WRITE','PROVIDER_READBACK','ARCHIVE_READBACK','FINALIZE'
  )),
  expected_state_version bigint NOT NULL CHECK (expected_state_version >= 0),
  envelope_sha256 text CHECK (envelope_sha256 IS NULL OR envelope_sha256 ~ '^[0-9a-f]{64}$'),
  event_payload jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(event_payload) = 'object'),
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  CONSTRAINT vera_memory_epoch_event_state_version_uq UNIQUE (subject_id, state_version),
  CONSTRAINT vera_memory_epoch_event_operation_uq UNIQUE (subject_id, operation_id, event_kind),
  CONSTRAINT vera_memory_epoch_event_version_step_ck CHECK (state_version = expected_state_version + 1)
);

CREATE TABLE public.vera_memory_epoch_provider_receipts_v1 (
  receipt_id uuid PRIMARY KEY,
  observation_ordinal bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  subject_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_class text NOT NULL CHECK (provider_class IN ('SUPABASE_RUNTIME','GOOGLE_DRIVE_DURABLE')),
  provider_identity text NOT NULL CHECK (provider_identity <> ''),
  provider_locator text NOT NULL CHECK (provider_locator <> ''),
  provider_revision_or_version text,
  operation_id text NOT NULL CHECK (operation_id <> ''),
  project_id text NOT NULL CHECK (project_id <> ''),
  branch_id text NOT NULL CHECK (branch_id <> ''),
  logical_memory_id uuid NOT NULL,
  epoch_id text NOT NULL CHECK (epoch_id = 'R9B0'),
  original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
  admission_metadata_sha256 text NOT NULL CHECK (admission_metadata_sha256 ~ '^[0-9a-f]{64}$'),
  envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
  written_byte_length bigint NOT NULL CHECK (written_byte_length > 0),
  write_observation_time timestamptz,
  readback_time timestamptz NOT NULL,
  readback_byte_length bigint NOT NULL CHECK (readback_byte_length >= 0),
  readback_sha256 text NOT NULL CHECK (readback_sha256 ~ '^[0-9a-f]{64}$'),
  verifier_route text NOT NULL CHECK (verifier_route <> ''),
  result text NOT NULL CHECK (result IN ('VERIFIED_EXACT','ABSENT','AMBIGUOUS','MISMATCH','ERROR')),
  limitations jsonb NOT NULL,
  CONSTRAINT vera_memory_epoch_provider_subject_fk FOREIGN KEY
    (subject_id, project_id, branch_id, logical_memory_id, epoch_id)
    REFERENCES public.vera_memory_epoch_subjects_v1
    (subject_id, project_id, branch_id, logical_memory_id, epoch_id)
    ON DELETE RESTRICT,
  CONSTRAINT vera_memory_epoch_provider_operation_uq UNIQUE (subject_id, provider_class, operation_id),
  CONSTRAINT vera_memory_epoch_provider_verified_ck CHECK (
    result <> 'VERIFIED_EXACT'
    OR (
      readback_sha256 = envelope_sha256
      AND readback_byte_length = written_byte_length
    )
  ),
  CONSTRAINT vera_memory_epoch_provider_mismatch_ck CHECK (
    result <> 'MISMATCH'
    OR readback_sha256 <> envelope_sha256
    OR readback_byte_length <> written_byte_length
  )
);

CREATE TABLE public.vera_memory_epoch_archive_receipts_v1 (
  archive_receipt_id uuid PRIMARY KEY,
  subject_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  project_id text NOT NULL CHECK (project_id <> ''),
  branch_id text NOT NULL CHECK (branch_id <> ''),
  logical_memory_id uuid NOT NULL,
  epoch_id text NOT NULL CHECK (epoch_id = 'R9B0'),
  original_source_locator text NOT NULL CHECK (original_source_locator <> ''),
  original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
  original_byte_length bigint NOT NULL CHECK (original_byte_length >= 0),
  original_provenance_digest text NOT NULL CHECK (original_provenance_digest ~ '^[0-9a-f]{64}$'),
  archive_bundle_id text NOT NULL CHECK (archive_bundle_id <> ''),
  archive_generation text NOT NULL CHECK (archive_generation <> ''),
  archive_container_sha256 text CHECK (archive_container_sha256 IS NULL OR archive_container_sha256 ~ '^[0-9a-f]{64}$'),
  archive_entry_path text NOT NULL CHECK (archive_entry_path <> ''),
  compression_method text NOT NULL CHECK (compression_method <> ''),
  archive_member_sha256 text CHECK (archive_member_sha256 IS NULL OR archive_member_sha256 ~ '^[0-9a-f]{64}$'),
  extracted_readback_byte_length bigint CHECK (extracted_readback_byte_length IS NULL OR extracted_readback_byte_length >= 0),
  extracted_readback_sha256 text CHECK (extracted_readback_sha256 IS NULL OR extracted_readback_sha256 ~ '^[0-9a-f]{64}$'),
  readback_time timestamptz NOT NULL,
  verifier_identity text NOT NULL CHECK (verifier_identity <> ''),
  admission_receipt_id uuid NOT NULL REFERENCES public.vera_memory_epoch_events_v1(event_id) ON DELETE RESTRICT,
  drive_receipt_id uuid NOT NULL REFERENCES public.vera_memory_epoch_provider_receipts_v1(receipt_id) ON DELETE RESTRICT,
  supabase_receipt_id uuid NOT NULL REFERENCES public.vera_memory_epoch_provider_receipts_v1(receipt_id) ON DELETE RESTRICT,
  operation_id text NOT NULL CHECK (operation_id <> ''),
  result text NOT NULL CHECK (result IN ('VERIFIED_EXACT','ABSENT','AMBIGUOUS','MISMATCH','ERROR')),
  limitations jsonb NOT NULL,
  CONSTRAINT vera_memory_epoch_archive_subject_fk FOREIGN KEY
    (subject_id, project_id, branch_id, logical_memory_id, epoch_id)
    REFERENCES public.vera_memory_epoch_subjects_v1
    (subject_id, project_id, branch_id, logical_memory_id, epoch_id)
    ON DELETE RESTRICT,
  CONSTRAINT vera_memory_epoch_archive_operation_uq UNIQUE (subject_id, operation_id),
  CONSTRAINT vera_memory_epoch_archive_verified_ck CHECK (
    result <> 'VERIFIED_EXACT'
    OR (
      archive_container_sha256 IS NOT NULL
      AND archive_member_sha256 = original_sha256
      AND extracted_readback_sha256 = original_sha256
      AND extracted_readback_byte_length = original_byte_length
    )
  ),
  CONSTRAINT vera_memory_epoch_archive_mismatch_ck CHECK (
    result <> 'MISMATCH'
    OR extracted_readback_sha256 IS DISTINCT FROM original_sha256
    OR extracted_readback_byte_length IS DISTINCT FROM original_byte_length
  )
);

ALTER TABLE public.vera_memory_epoch_subjects_v1 OWNER TO postgres;
ALTER TABLE public.vera_memory_epoch_events_v1 OWNER TO postgres;
ALTER TABLE public.vera_memory_epoch_provider_receipts_v1 OWNER TO postgres;
ALTER TABLE public.vera_memory_epoch_archive_receipts_v1 OWNER TO postgres;

CREATE FUNCTION public._vera_memory_epoch_guard_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $guard$
BEGIN
  IF TG_TABLE_NAME = 'vera_memory_epoch_subjects_v1' THEN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'BT2_EPOCH_SUBJECT_GUARD_UNEXPECTED_OP: %', TG_OP;
    END IF;

    IF NEW.subject_id IS DISTINCT FROM OLD.subject_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.branch_id IS DISTINCT FROM OLD.branch_id
       OR NEW.logical_memory_id IS DISTINCT FROM OLD.logical_memory_id
       OR NEW.epoch_id IS DISTINCT FROM OLD.epoch_id
       OR NEW.current_attempt_id IS DISTINCT FROM OLD.current_attempt_id
       OR NEW.source_provider IS DISTINCT FROM OLD.source_provider
       OR NEW.source_locator IS DISTINCT FROM OLD.source_locator
       OR NEW.source_version_or_generation IS DISTINCT FROM OLD.source_version_or_generation
       OR NEW.original_sha256 IS DISTINCT FROM OLD.original_sha256
       OR NEW.original_byte_length IS DISTINCT FROM OLD.original_byte_length
       OR NEW.original_provenance_digest IS DISTINCT FROM OLD.original_provenance_digest
       OR NEW.privacy_scope IS DISTINCT FROM OLD.privacy_scope
       OR NEW.lifecycle_status IS DISTINCT FROM OLD.lifecycle_status
       OR NEW.currentness_rule IS DISTINCT FROM OLD.currentness_rule
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'BT2_EPOCH_IMMUTABLE_SUBJECT_BINDING';
    END IF;

    IF OLD.admission_generation_or_digest IS NOT NULL
       AND NEW.admission_generation_or_digest IS DISTINCT FROM OLD.admission_generation_or_digest THEN
      RAISE EXCEPTION 'BT2_EPOCH_ADMISSION_BINDING_IMMUTABLE';
    END IF;
    IF OLD.admission_metadata_sha256 IS NOT NULL
       AND NEW.admission_metadata_sha256 IS DISTINCT FROM OLD.admission_metadata_sha256 THEN
      RAISE EXCEPTION 'BT2_EPOCH_ADMISSION_METADATA_IMMUTABLE';
    END IF;
    IF OLD.envelope_sha256 IS NOT NULL AND NEW.envelope_sha256 IS DISTINCT FROM OLD.envelope_sha256 THEN
      RAISE EXCEPTION 'BT2_EPOCH_ENVELOPE_DIGEST_IMMUTABLE';
    END IF;
    IF OLD.envelope_byte_length IS NOT NULL AND NEW.envelope_byte_length IS DISTINCT FROM OLD.envelope_byte_length THEN
      RAISE EXCEPTION 'BT2_EPOCH_ENVELOPE_LENGTH_IMMUTABLE';
    END IF;
    IF OLD.canonical_envelope IS NOT NULL AND NEW.canonical_envelope IS DISTINCT FROM OLD.canonical_envelope THEN
      RAISE EXCEPTION 'BT2_EPOCH_SUPABASE_FULL_COPY_IMMUTABLE';
    END IF;

    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME IN (
    'vera_memory_epoch_events_v1',
    'vera_memory_epoch_provider_receipts_v1',
    'vera_memory_epoch_archive_receipts_v1'
  ) AND TG_OP IN ('UPDATE','DELETE') THEN
    RAISE EXCEPTION 'BT2_EPOCH_APPEND_ONLY: %.% forbids %', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP;
  END IF;

  RAISE EXCEPTION 'BT2_EPOCH_GUARD_UNEXPECTED_TARGET: %.% %', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP;
END
$guard$;

REVOKE ALL ON FUNCTION public._vera_memory_epoch_guard_v1() FROM PUBLIC, anon, authenticated, service_role;

CREATE TRIGGER vera_memory_epoch_subject_immutable_guard_v1
BEFORE UPDATE ON public.vera_memory_epoch_subjects_v1
FOR EACH ROW EXECUTE FUNCTION public._vera_memory_epoch_guard_v1();

CREATE TRIGGER vera_memory_epoch_events_append_only_guard_v1
BEFORE UPDATE OR DELETE ON public.vera_memory_epoch_events_v1
FOR EACH ROW EXECUTE FUNCTION public._vera_memory_epoch_guard_v1();

CREATE TRIGGER vera_memory_epoch_provider_receipts_append_only_guard_v1
BEFORE UPDATE OR DELETE ON public.vera_memory_epoch_provider_receipts_v1
FOR EACH ROW EXECUTE FUNCTION public._vera_memory_epoch_guard_v1();

CREATE TRIGGER vera_memory_epoch_archive_receipts_append_only_guard_v1
BEFORE UPDATE OR DELETE ON public.vera_memory_epoch_archive_receipts_v1
FOR EACH ROW EXECUTE FUNCTION public._vera_memory_epoch_guard_v1();

CREATE INDEX vera_memory_epoch_provider_current_lookup_idx
  ON public.vera_memory_epoch_provider_receipts_v1
  (subject_id, attempt_id, provider_class, envelope_sha256, observation_ordinal DESC);

CREATE INDEX vera_memory_epoch_archive_current_lookup_idx
  ON public.vera_memory_epoch_archive_receipts_v1
  (subject_id, attempt_id, readback_time DESC);

ALTER TABLE public.vera_memory_epoch_subjects_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_subjects_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_events_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_events_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_provider_receipts_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_provider_receipts_v1 FORCE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_archive_receipts_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vera_memory_epoch_archive_receipts_v1 FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE
  public.vera_memory_epoch_subjects_v1,
  public.vera_memory_epoch_events_v1,
  public.vera_memory_epoch_provider_receipts_v1,
  public.vera_memory_epoch_archive_receipts_v1
FROM PUBLIC, anon, authenticated, service_role;

-- The identity sequence is a separate privilege-bearing object. Supabase public-schema
-- default sequence ACLs may expose client/service roles unless explicitly revoked.
REVOKE ALL ON SEQUENCE public.vera_memory_epoch_provider_receipts_v1_observation_ordinal_seq
FROM PUBLIC, anon, authenticated, service_role;

-- No RLS policies are created in v1. Initial callable posture is owner/postgres only.
-- No service_role raw table privilege or RPC EXECUTE is granted by this migration.

CREATE FUNCTION public.vera_memory_epoch_get_status_v1(
  p_project_id text,
  p_branch_id text,
  p_logical_memory_id uuid,
  p_epoch_id text DEFAULT 'R9B0'
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
BEGIN
  SELECT * INTO s
  FROM public.vera_memory_epoch_subjects_v1
  WHERE project_id = p_project_id
    AND branch_id = p_branch_id
    AND logical_memory_id = p_logical_memory_id
    AND epoch_id = p_epoch_id;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object(
      'exists', false,
      'state', 'UNVERIFIED_PRE_R9B0',
      'state_version', 0,
      'project_id', p_project_id,
      'branch_id', p_branch_id,
      'logical_memory_id', p_logical_memory_id,
      'epoch_id', p_epoch_id,
      'authority_ceiling', 'HISTORICAL_UNVERIFIED_ONLY'
    );
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'exists', true,
    'subject_id', s.subject_id,
    'project_id', s.project_id,
    'branch_id', s.branch_id,
    'logical_memory_id', s.logical_memory_id,
    'epoch_id', s.epoch_id,
    'state', s.state,
    'state_version', s.state_version,
    'current_attempt_id', s.current_attempt_id,
    'original_sha256', s.original_sha256,
    'admission_metadata_sha256', s.admission_metadata_sha256,
    'envelope_sha256', s.envelope_sha256,
    'envelope_byte_length', s.envelope_byte_length,
    'privacy_scope', s.privacy_scope,
    'lifecycle_status', s.lifecycle_status,
    'currentness_rule', s.currentness_rule,
    'provider_receipts', (
      SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'receipt_id', pr.receipt_id,
        'provider_class', pr.provider_class,
        'attempt_id', pr.attempt_id,
        'operation_id', pr.operation_id,
        'envelope_sha256', pr.envelope_sha256,
        'observation_ordinal', pr.observation_ordinal,
        'readback_time', pr.readback_time,
        'result', pr.result
      ) ORDER BY pr.observation_ordinal), '[]'::jsonb)
      FROM public.vera_memory_epoch_provider_receipts_v1 pr
      WHERE pr.subject_id = s.subject_id
    ),
    'archive_receipts', (
      SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'archive_receipt_id', ar.archive_receipt_id,
        'attempt_id', ar.attempt_id,
        'operation_id', ar.operation_id,
        'archive_generation', ar.archive_generation,
        'readback_time', ar.readback_time,
        'result', ar.result
      ) ORDER BY ar.readback_time), '[]'::jsonb)
      FROM public.vera_memory_epoch_archive_receipts_v1 ar
      WHERE ar.subject_id = s.subject_id
    ),
    'latest_incomplete_reasons', (
      SELECT e.event_payload->'incomplete_reasons'
      FROM public.vera_memory_epoch_events_v1 e
      WHERE e.subject_id = s.subject_id
        AND e.new_state = 'MIGRATION_INCOMPLETE'
      ORDER BY e.state_version DESC
      LIMIT 1
    ),
    'present_truth_promoted', false
  );
END
$fn$;

CREATE FUNCTION public.vera_memory_epoch_resume_incomplete_v1(
  p_project_id text,
  p_branch_id text,
  p_logical_memory_id uuid,
  p_epoch_id text DEFAULT 'R9B0'
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  sup_exact boolean;
  drv_exact boolean;
  arch_exact boolean;
BEGIN
  SELECT * INTO s
  FROM public.vera_memory_epoch_subjects_v1
  WHERE project_id = p_project_id
    AND branch_id = p_branch_id
    AND logical_memory_id = p_logical_memory_id
    AND epoch_id = p_epoch_id;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object(
      'state', 'UNVERIFIED_PRE_R9B0',
      'side_effect_free', true,
      'next_action', 'BEGIN_REVALIDATION_IF_AUTHORIZED'
    );
  END IF;

  SELECT COALESCE((
    SELECT pr.result = 'VERIFIED_EXACT' AND pr.envelope_sha256 = s.envelope_sha256
    FROM public.vera_memory_epoch_provider_receipts_v1 pr
    WHERE pr.subject_id = s.subject_id
      AND pr.attempt_id = s.current_attempt_id
      AND pr.provider_class = 'SUPABASE_RUNTIME'
    ORDER BY pr.observation_ordinal DESC
    LIMIT 1
  ), false) INTO sup_exact;

  SELECT COALESCE((
    SELECT pr.result = 'VERIFIED_EXACT' AND pr.envelope_sha256 = s.envelope_sha256
    FROM public.vera_memory_epoch_provider_receipts_v1 pr
    WHERE pr.subject_id = s.subject_id
      AND pr.attempt_id = s.current_attempt_id
      AND pr.provider_class = 'GOOGLE_DRIVE_DURABLE'
    ORDER BY pr.observation_ordinal DESC
    LIMIT 1
  ), false) INTO drv_exact;

  SELECT EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_archive_receipts_v1 ar
    WHERE ar.subject_id = s.subject_id
      AND ar.attempt_id = s.current_attempt_id
      AND ar.result = 'VERIFIED_EXACT'
      AND ar.original_sha256 = s.original_sha256
      AND ar.extracted_readback_sha256 = s.original_sha256
      AND ar.extracted_readback_byte_length = s.original_byte_length
  ) INTO arch_exact;

  RETURN pg_catalog.jsonb_build_object(
    'subject_id', s.subject_id,
    'state', s.state,
    'state_version', s.state_version,
    'attempt_id', s.current_attempt_id,
    'supabase_exact', sup_exact,
    'drive_exact', drv_exact,
    'archive_exact', arch_exact,
    'side_effect_free', true,
    'next_action', CASE
      WHEN s.state = 'MIGRATION_CONFLICTED' THEN 'NO_GENERIC_RESOLVER_REVIEW_REQUIRED'
      WHEN s.state = 'R9B0_VERIFIED_ACTIVE' THEN 'NONE_ALREADY_ACTIVE'
      WHEN NOT sup_exact THEN 'INSPECT_OR_VERIFY_SUPABASE_RUNTIME'
      WHEN NOT drv_exact THEN 'INSPECT_OR_VERIFY_GOOGLE_DRIVE_DURABLE'
      WHEN NOT arch_exact THEN 'REESTABLISH_PENDING_ARCHIVE_THEN_INSPECT_OR_VERIFY_ARCHIVE'
      ELSE 'FINALIZE_IF_ALL_CURRENT_GATES_STILL_HOLD'
    END,
    'present_truth_promoted', false
  );
END
$fn$;

-- Stable operation replay contract for all six mutating RPCs:
-- each mutation persists event_payload.replay_binding as the complete material tuple.
-- Exact tuple retry => REPLAY; same operation_id with any changed binding => CONFLICT before mutation.
-- Freeform p_event_payload and p_limitations are diagnostic-only/non-binding and are explicitly labeled as such.

CREATE FUNCTION public.vera_memory_epoch_begin_revalidation_v1(
  p_subject_id uuid,
  p_project_id text,
  p_branch_id text,
  p_logical_memory_id uuid,
  p_epoch_id text,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_source_provider text,
  p_source_locator text,
  p_source_version_or_generation text,
  p_original_sha256 text,
  p_original_byte_length bigint,
  p_original_provenance_digest text,
  p_privacy_scope text,
  p_lifecycle_status text,
  p_currentness_rule jsonb,
  p_event_id uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  e public.vera_memory_epoch_events_v1%ROWTYPE;
  payload jsonb;
  replay_binding jsonb;
BEGIN
  IF p_epoch_id <> 'R9B0' OR p_expected_prior_state <> 'UNVERIFIED_PRE_R9B0' OR p_expected_state_version <> 0 THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','BEGIN_REQUIRES_VIRTUAL_UNVERIFIED_V0');
  END IF;
  IF p_original_sha256 !~ '^[0-9a-f]{64}$' OR p_original_provenance_digest !~ '^[0-9a-f]{64}$' OR p_original_byte_length < 0 THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','INVALID_SOURCE_BINDING');
  END IF;

  replay_binding := pg_catalog.jsonb_build_object(
    'subject_id',p_subject_id,'project_id',p_project_id,'branch_id',p_branch_id,
    'logical_memory_id',p_logical_memory_id,'epoch_id',p_epoch_id,
    'expected_prior_state',p_expected_prior_state,'expected_state_version',p_expected_state_version,
    'attempt_id',p_attempt_id,'operation_id',p_operation_id,'event_id',p_event_id,
    'source_provider',p_source_provider,'source_locator',p_source_locator,
    'source_version_or_generation',p_source_version_or_generation,
    'original_sha256',p_original_sha256,'original_byte_length',p_original_byte_length,
    'original_provenance_digest',p_original_provenance_digest,'privacy_scope',p_privacy_scope,
    'lifecycle_status',p_lifecycle_status,'currentness_rule',p_currentness_rule
  );

  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
    p_project_id || E'\x1f' || p_branch_id || E'\x1f' || p_logical_memory_id::text || E'\x1f' || p_epoch_id, 0));

  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1
  WHERE project_id=p_project_id AND branch_id=p_branch_id AND logical_memory_id=p_logical_memory_id AND epoch_id=p_epoch_id
  FOR UPDATE;

  IF FOUND THEN
    SELECT * INTO e FROM public.vera_memory_epoch_events_v1
    WHERE subject_id=s.subject_id AND operation_id=p_operation_id AND event_kind='BEGIN_REVALIDATION';
    IF FOUND THEN
      IF e.event_payload->'replay_binding' = replay_binding THEN
        RETURN pg_catalog.jsonb_build_object('status','REPLAY','subject_id',s.subject_id,'state',s.state,'state_version',s.state_version,'event_id',e.event_id);
      END IF;
      RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','subject_id',s.subject_id,'state',s.state,'state_version',s.state_version);
  END IF;

  payload := pg_catalog.jsonb_build_object(
    'source_provider',p_source_provider,'source_locator',p_source_locator,
    'source_version_or_generation',p_source_version_or_generation,
    'original_sha256',p_original_sha256,'original_byte_length',p_original_byte_length,
    'original_provenance_digest',p_original_provenance_digest,
    'privacy_scope',p_privacy_scope,'lifecycle_status',p_lifecycle_status,
    'currentness_rule',p_currentness_rule,
    'replay_binding',replay_binding,
    'diagnostic_nonbinding_fields','[]'::jsonb
  );

  INSERT INTO public.vera_memory_epoch_subjects_v1(
    subject_id,project_id,branch_id,logical_memory_id,epoch_id,state,state_version,current_attempt_id,
    source_provider,source_locator,source_version_or_generation,original_sha256,original_byte_length,
    original_provenance_digest,privacy_scope,lifecycle_status,currentness_rule
  ) VALUES (
    p_subject_id,p_project_id,p_branch_id,p_logical_memory_id,p_epoch_id,'REVALIDATING_R9B0',1,p_attempt_id,
    p_source_provider,p_source_locator,p_source_version_or_generation,p_original_sha256,p_original_byte_length,
    p_original_provenance_digest,p_privacy_scope,p_lifecycle_status,p_currentness_rule
  );

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,1,'UNVERIFIED_PRE_R9B0','REVALIDATING_R9B0',p_attempt_id,p_operation_id,
    'BEGIN_REVALIDATION',0,NULL,payload
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','subject_id',p_subject_id,'state','REVALIDATING_R9B0','state_version',1,'event_id',p_event_id);
END
$fn$;

CREATE FUNCTION public.vera_memory_epoch_record_admission_v1(
  p_subject_id uuid,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_admitted boolean,
  p_admission_generation_or_digest text,
  p_admission_metadata_sha256 text,
  p_envelope_sha256 text,
  p_envelope_byte_length bigint,
  p_event_id uuid,
  p_event_payload jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  e public.vera_memory_epoch_events_v1%ROWTYPE;
  next_state text;
  next_version bigint;
  replay_binding jsonb;
BEGIN
  replay_binding := pg_catalog.jsonb_build_object(
    'subject_id',p_subject_id,'expected_prior_state',p_expected_prior_state,
    'expected_state_version',p_expected_state_version,'attempt_id',p_attempt_id,
    'operation_id',p_operation_id,'event_id',p_event_id,'admitted',p_admitted,
    'admission_generation_or_digest',p_admission_generation_or_digest,
    'admission_metadata_sha256',p_admission_metadata_sha256,'envelope_sha256',p_envelope_sha256,
    'envelope_byte_length',p_envelope_byte_length
  );
  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=p_subject_id FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUBJECT_ABSENT'); END IF;

  SELECT * INTO e FROM public.vera_memory_epoch_events_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='ADMISSION';
  IF FOUND THEN
    IF e.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','event_id',e.event_id,'state',e.new_state,'state_version',e.state_version);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  IF s.state <> p_expected_prior_state OR s.state_version <> p_expected_state_version OR s.current_attempt_id IS DISTINCT FROM p_attempt_id THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','state',s.state,'state_version',s.state_version,'attempt_id',s.current_attempt_id);
  END IF;
  IF s.state <> 'REVALIDATING_R9B0' THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','ADMISSION_REQUIRES_REVALIDATING');
  END IF;
  IF p_admission_metadata_sha256 !~ '^[0-9a-f]{64}$' OR p_envelope_sha256 !~ '^[0-9a-f]{64}$' OR p_envelope_byte_length <= 0 OR p_admission_generation_or_digest IS NULL OR p_admission_generation_or_digest='' THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','INVALID_ADMISSION_BINDING');
  END IF;

  next_state := CASE WHEN p_admitted THEN 'ADMISSION_VERIFIED' ELSE 'R9B0_ADMISSION_REJECTED' END;
  next_version := s.state_version + 1;

  UPDATE public.vera_memory_epoch_subjects_v1
  SET state=next_state,state_version=next_version,
      admission_generation_or_digest=p_admission_generation_or_digest,
      admission_metadata_sha256=p_admission_metadata_sha256,
      envelope_sha256=p_envelope_sha256,
      envelope_byte_length=p_envelope_byte_length,
      updated_at=pg_catalog.clock_timestamp()
  WHERE subject_id=p_subject_id AND state_version=p_expected_state_version AND state=p_expected_prior_state;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','LOST_UPDATE');
  END IF;

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,next_version,p_expected_prior_state,next_state,p_attempt_id,p_operation_id,'ADMISSION',
    p_expected_state_version,p_envelope_sha256,
    (COALESCE(p_event_payload,'{}'::jsonb) - 'replay_binding' - 'diagnostic_nonbinding_fields') ||
    pg_catalog.jsonb_build_object(
      'admitted',p_admitted,'admission_metadata_sha256',p_admission_metadata_sha256,
      'admission_generation_or_digest',p_admission_generation_or_digest,
      'replay_binding',replay_binding,'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_event_payload')
    )
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','event_id',p_event_id,'state',next_state,'state_version',next_version);
END
$fn$;

CREATE FUNCTION public.vera_memory_epoch_write_supabase_replica_v1(
  p_subject_id uuid,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_envelope_sha256 text,
  p_canonical_envelope bytea,
  p_event_id uuid,
  p_event_payload jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  e public.vera_memory_epoch_events_v1%ROWTYPE;
  actual_sha text;
  next_state text;
  next_version bigint;
  replay_binding jsonb;
BEGIN
  actual_sha := pg_catalog.encode(extensions.digest(p_canonical_envelope,'sha256'),'hex');
  replay_binding := pg_catalog.jsonb_build_object(
    'subject_id',p_subject_id,'expected_prior_state',p_expected_prior_state,
    'expected_state_version',p_expected_state_version,'attempt_id',p_attempt_id,
    'operation_id',p_operation_id,'event_id',p_event_id,'envelope_sha256',p_envelope_sha256,
    'envelope_byte_length',CASE WHEN p_canonical_envelope IS NULL THEN NULL ELSE pg_catalog.octet_length(p_canonical_envelope) END
  );
  IF p_canonical_envelope IS NULL OR pg_catalog.octet_length(p_canonical_envelope) <= 0 OR actual_sha <> p_envelope_sha256 THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','ENVELOPE_BYTES_DIGEST_MISMATCH');
  END IF;

  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=p_subject_id FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUBJECT_ABSENT'); END IF;

  SELECT * INTO e FROM public.vera_memory_epoch_events_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='SUPABASE_REPLICA_WRITE';
  IF FOUND THEN
    IF e.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','event_id',e.event_id,'state',s.state,'state_version',s.state_version,'envelope_sha256',p_envelope_sha256);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  IF s.state <> p_expected_prior_state OR s.state_version <> p_expected_state_version OR s.current_attempt_id IS DISTINCT FROM p_attempt_id THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','state',s.state,'state_version',s.state_version);
  END IF;
  IF s.state NOT IN ('ADMISSION_VERIFIED','MIGRATION_INCOMPLETE') THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUPABASE_WRITE_REQUIRES_ADMITTED_OR_INCOMPLETE');
  END IF;
  IF s.envelope_sha256 IS DISTINCT FROM p_envelope_sha256 OR s.envelope_byte_length IS DISTINCT FROM pg_catalog.octet_length(p_canonical_envelope) THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','ADMISSION_ENVELOPE_BINDING_MISMATCH');
  END IF;
  IF s.canonical_envelope IS NOT NULL AND s.canonical_envelope <> p_canonical_envelope THEN
    next_version := s.state_version + 1;
    UPDATE public.vera_memory_epoch_subjects_v1
      SET state='MIGRATION_CONFLICTED',state_version=next_version,updated_at=pg_catalog.clock_timestamp()
      WHERE subject_id=p_subject_id AND state_version=p_expected_state_version;
    INSERT INTO public.vera_memory_epoch_events_v1(
      event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
      expected_state_version,envelope_sha256,event_payload
    ) VALUES (
      p_event_id,p_subject_id,next_version,p_expected_prior_state,'MIGRATION_CONFLICTED',p_attempt_id,p_operation_id,
      'SUPABASE_REPLICA_WRITE',p_expected_state_version,p_envelope_sha256,
      (COALESCE(p_event_payload,'{}'::jsonb) - 'replay_binding' - 'diagnostic_nonbinding_fields') ||
      pg_catalog.jsonb_build_object(
        'conflict_reason','DIVERGENT_EXISTING_SUPABASE_BYTES','replay_binding',replay_binding,
        'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_event_payload')
      )
    );
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','state','MIGRATION_CONFLICTED','state_version',next_version,'event_id',p_event_id);
  END IF;

  next_state := 'MIGRATION_INCOMPLETE';
  next_version := s.state_version + 1;
  UPDATE public.vera_memory_epoch_subjects_v1
    SET canonical_envelope=p_canonical_envelope,state=next_state,state_version=next_version,updated_at=pg_catalog.clock_timestamp()
    WHERE subject_id=p_subject_id AND state_version=p_expected_state_version AND state=p_expected_prior_state;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','LOST_UPDATE'); END IF;

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,next_version,p_expected_prior_state,next_state,p_attempt_id,p_operation_id,
    'SUPABASE_REPLICA_WRITE',p_expected_state_version,p_envelope_sha256,
    (COALESCE(p_event_payload,'{}'::jsonb) - 'replay_binding' - 'diagnostic_nonbinding_fields') ||
    pg_catalog.jsonb_build_object(
      'incomplete_reasons',pg_catalog.jsonb_build_array('SUPABASE_WRITE_REQUIRES_INDEPENDENT_READBACK_AND_DRIVE'),
      'replay_binding',replay_binding,'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_event_payload')
    )
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','event_id',p_event_id,'state',next_state,'state_version',next_version,'envelope_sha256',p_envelope_sha256,'byte_length',pg_catalog.octet_length(p_canonical_envelope));
END
$fn$;

CREATE FUNCTION public.vera_memory_epoch_record_provider_readback_v1(
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
    WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='PROVIDER_READBACK';
    IF FOUND AND e.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','receipt_id',pr.receipt_id,'result',pr.result,'state',s.state,'state_version',s.state_version);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  SELECT * INTO e FROM public.vera_memory_epoch_events_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='PROVIDER_READBACK';
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

CREATE FUNCTION public.vera_memory_epoch_record_archive_readback_v1(
  p_archive_receipt_id uuid,
  p_subject_id uuid,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_event_id uuid,
  p_original_source_locator text,
  p_archive_bundle_id text,
  p_archive_generation text,
  p_archive_container_sha256 text,
  p_archive_entry_path text,
  p_compression_method text,
  p_archive_member_sha256 text,
  p_extracted_readback_byte_length bigint,
  p_extracted_readback_sha256 text,
  p_readback_time timestamptz,
  p_verifier_identity text,
  p_admission_receipt_id uuid,
  p_drive_receipt_id uuid,
  p_supabase_receipt_id uuid,
  p_result text,
  p_limitations jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  ar public.vera_memory_epoch_archive_receipts_v1%ROWTYPE;
  dr public.vera_memory_epoch_provider_receipts_v1%ROWTYPE;
  sr public.vera_memory_epoch_provider_receipts_v1%ROWTYPE;
  ae public.vera_memory_epoch_events_v1%ROWTYPE;
  next_state text;
  next_version bigint;
  replay_binding jsonb;
BEGIN
  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=p_subject_id FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUBJECT_ABSENT'); END IF;
  IF p_original_source_locator IS DISTINCT FROM s.source_locator THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','ARCHIVE_SOURCE_LOCATOR_MISMATCH');
  END IF;

  replay_binding := pg_catalog.jsonb_build_object(
    'archive_receipt_id',p_archive_receipt_id,'subject_id',p_subject_id,
    'expected_prior_state',p_expected_prior_state,'expected_state_version',p_expected_state_version,
    'attempt_id',p_attempt_id,'operation_id',p_operation_id,'event_id',p_event_id,
    'original_source_locator',s.source_locator,'archive_bundle_id',p_archive_bundle_id,
    'archive_generation',p_archive_generation,'archive_container_sha256',p_archive_container_sha256,
    'archive_entry_path',p_archive_entry_path,'compression_method',p_compression_method,
    'archive_member_sha256',p_archive_member_sha256,
    'extracted_readback_byte_length',p_extracted_readback_byte_length,
    'extracted_readback_sha256',p_extracted_readback_sha256,'readback_time',p_readback_time,
    'verifier_identity',p_verifier_identity,'admission_receipt_id',p_admission_receipt_id,
    'drive_receipt_id',p_drive_receipt_id,'supabase_receipt_id',p_supabase_receipt_id,'result',p_result
  );

  SELECT * INTO ar FROM public.vera_memory_epoch_archive_receipts_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id;
  IF FOUND THEN
    SELECT * INTO ae FROM public.vera_memory_epoch_events_v1
    WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='ARCHIVE_READBACK';
    IF FOUND AND ae.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','archive_receipt_id',ar.archive_receipt_id,'result',ar.result,'state',s.state,'state_version',s.state_version);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  IF s.state <> p_expected_prior_state OR s.state_version <> p_expected_state_version OR s.current_attempt_id IS DISTINCT FROM p_attempt_id THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','state',s.state,'state_version',s.state_version);
  END IF;
  IF s.state <> 'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','ARCHIVE_READBACK_REQUIRES_DUAL_STORE_PENDING','state',s.state);
  END IF;

  SELECT * INTO dr FROM public.vera_memory_epoch_provider_receipts_v1 WHERE receipt_id=p_drive_receipt_id;
  SELECT * INTO sr FROM public.vera_memory_epoch_provider_receipts_v1 WHERE receipt_id=p_supabase_receipt_id;
  SELECT * INTO ae FROM public.vera_memory_epoch_events_v1 WHERE event_id=p_admission_receipt_id;

  IF dr.receipt_id IS NULL OR sr.receipt_id IS NULL OR ae.event_id IS NULL
     OR dr.subject_id<>s.subject_id OR sr.subject_id<>s.subject_id OR ae.subject_id<>s.subject_id
     OR dr.attempt_id<>p_attempt_id OR sr.attempt_id<>p_attempt_id
     OR dr.provider_class<>'GOOGLE_DRIVE_DURABLE' OR sr.provider_class<>'SUPABASE_RUNTIME'
     OR dr.result<>'VERIFIED_EXACT' OR sr.result<>'VERIFIED_EXACT'
     OR dr.envelope_sha256<>s.envelope_sha256 OR sr.envelope_sha256<>s.envelope_sha256
     OR ae.event_kind<>'ADMISSION' OR ae.new_state<>'ADMISSION_VERIFIED' THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','ARCHIVE_PREDECESSOR_RECEIPTS_INVALID');
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_provider_receipts_v1 x
    WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class=dr.provider_class
      AND x.observation_ordinal > dr.observation_ordinal
  ) OR EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_provider_receipts_v1 x
    WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class=sr.provider_class
      AND x.observation_ordinal > sr.observation_ordinal
  ) THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','ARCHIVE_REQUIRES_CURRENT_PROVIDER_RECEIPTS');
  END IF;

  INSERT INTO public.vera_memory_epoch_archive_receipts_v1(
    archive_receipt_id,subject_id,attempt_id,project_id,branch_id,logical_memory_id,epoch_id,
    original_source_locator,original_sha256,original_byte_length,original_provenance_digest,
    archive_bundle_id,archive_generation,archive_container_sha256,archive_entry_path,compression_method,
    archive_member_sha256,extracted_readback_byte_length,extracted_readback_sha256,readback_time,verifier_identity,
    admission_receipt_id,drive_receipt_id,supabase_receipt_id,operation_id,result,limitations
  ) VALUES (
    p_archive_receipt_id,s.subject_id,p_attempt_id,s.project_id,s.branch_id,s.logical_memory_id,s.epoch_id,
    s.source_locator,s.original_sha256,s.original_byte_length,s.original_provenance_digest,
    p_archive_bundle_id,p_archive_generation,p_archive_container_sha256,p_archive_entry_path,p_compression_method,
    p_archive_member_sha256,p_extracted_readback_byte_length,p_extracted_readback_sha256,p_readback_time,p_verifier_identity,
    p_admission_receipt_id,p_drive_receipt_id,p_supabase_receipt_id,p_operation_id,p_result,p_limitations
  );

  IF p_result='MISMATCH' THEN next_state := 'MIGRATION_CONFLICTED';
  ELSIF p_result IN ('ABSENT','AMBIGUOUS','ERROR') THEN next_state := 'MIGRATION_INCOMPLETE';
  ELSE next_state := 'DUAL_STORE_VERIFIED_PENDING_ARCHIVE';
  END IF;

  next_version := s.state_version + 1;
  UPDATE public.vera_memory_epoch_subjects_v1
    SET state=next_state,state_version=next_version,updated_at=pg_catalog.clock_timestamp()
    WHERE subject_id=p_subject_id AND state_version=p_expected_state_version AND state=p_expected_prior_state;
  IF NOT FOUND THEN RAISE EXCEPTION 'BT2_INTERNAL_CAS_LOST_AFTER_ARCHIVE_RECEIPT_INSERT'; END IF;

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,next_version,p_expected_prior_state,next_state,p_attempt_id,p_operation_id,'ARCHIVE_READBACK',
    p_expected_state_version,s.envelope_sha256,
    pg_catalog.jsonb_build_object(
      'archive_receipt_id',p_archive_receipt_id,'result',p_result,
      'replay_binding',replay_binding,'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_limitations'),
      'incomplete_reasons',CASE WHEN next_state='MIGRATION_INCOMPLETE' THEN pg_catalog.jsonb_build_array('ARCHIVE_NOT_VERIFIED_EXACT') ELSE '[]'::jsonb END
    )
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','archive_receipt_id',p_archive_receipt_id,'event_id',p_event_id,'state',next_state,'state_version',next_version,'result',p_result);
END
$fn$;

CREATE FUNCTION public.vera_memory_epoch_finalize_v1(
  p_subject_id uuid,
  p_expected_prior_state text,
  p_expected_state_version bigint,
  p_attempt_id uuid,
  p_operation_id text,
  p_event_id uuid,
  p_admission_receipt_id uuid,
  p_drive_receipt_id uuid,
  p_supabase_receipt_id uuid,
  p_archive_receipt_id uuid,
  p_event_payload jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
DECLARE
  s public.vera_memory_epoch_subjects_v1%ROWTYPE;
  e public.vera_memory_epoch_events_v1%ROWTYPE;
  ae public.vera_memory_epoch_events_v1%ROWTYPE;
  dr public.vera_memory_epoch_provider_receipts_v1%ROWTYPE;
  sr public.vera_memory_epoch_provider_receipts_v1%ROWTYPE;
  ar public.vera_memory_epoch_archive_receipts_v1%ROWTYPE;
  next_version bigint;
  replay_binding jsonb;
BEGIN
  replay_binding := pg_catalog.jsonb_build_object(
    'subject_id',p_subject_id,'expected_prior_state',p_expected_prior_state,
    'expected_state_version',p_expected_state_version,'attempt_id',p_attempt_id,
    'operation_id',p_operation_id,'event_id',p_event_id,
    'admission_receipt_id',p_admission_receipt_id,'drive_receipt_id',p_drive_receipt_id,
    'supabase_receipt_id',p_supabase_receipt_id,'archive_receipt_id',p_archive_receipt_id
  );
  SELECT * INTO s FROM public.vera_memory_epoch_subjects_v1 WHERE subject_id=p_subject_id FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','SUBJECT_ABSENT'); END IF;

  SELECT * INTO e FROM public.vera_memory_epoch_events_v1
  WHERE subject_id=p_subject_id AND operation_id=p_operation_id AND event_kind='FINALIZE';
  IF FOUND THEN
    IF e.event_payload->'replay_binding' = replay_binding THEN
      RETURN pg_catalog.jsonb_build_object('status','REPLAY','event_id',e.event_id,'state',e.new_state,'state_version',e.state_version);
    END IF;
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','OPERATION_ID_REBOUND');
  END IF;

  IF s.state <> p_expected_prior_state OR s.state_version <> p_expected_state_version OR s.current_attempt_id IS DISTINCT FROM p_attempt_id THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','state',s.state,'state_version',s.state_version);
  END IF;
  IF s.state <> 'DUAL_STORE_VERIFIED_PENDING_ARCHIVE' THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','FINALIZE_REQUIRES_DUAL_STORE_PENDING');
  END IF;

  SELECT * INTO ae FROM public.vera_memory_epoch_events_v1 WHERE event_id=p_admission_receipt_id;
  SELECT * INTO dr FROM public.vera_memory_epoch_provider_receipts_v1 WHERE receipt_id=p_drive_receipt_id;
  SELECT * INTO sr FROM public.vera_memory_epoch_provider_receipts_v1 WHERE receipt_id=p_supabase_receipt_id;
  SELECT * INTO ar FROM public.vera_memory_epoch_archive_receipts_v1 WHERE archive_receipt_id=p_archive_receipt_id;

  IF ae.event_id IS NULL OR dr.receipt_id IS NULL OR sr.receipt_id IS NULL OR ar.archive_receipt_id IS NULL
     OR ae.subject_id<>s.subject_id OR dr.subject_id<>s.subject_id OR sr.subject_id<>s.subject_id OR ar.subject_id<>s.subject_id
     OR ae.event_kind<>'ADMISSION' OR ae.new_state<>'ADMISSION_VERIFIED'
     OR dr.attempt_id<>p_attempt_id OR sr.attempt_id<>p_attempt_id OR ar.attempt_id<>p_attempt_id
     OR dr.provider_class<>'GOOGLE_DRIVE_DURABLE' OR sr.provider_class<>'SUPABASE_RUNTIME'
     OR dr.result<>'VERIFIED_EXACT' OR sr.result<>'VERIFIED_EXACT' OR ar.result<>'VERIFIED_EXACT'
     OR dr.envelope_sha256<>s.envelope_sha256 OR sr.envelope_sha256<>s.envelope_sha256
     OR dr.readback_sha256<>s.envelope_sha256 OR sr.readback_sha256<>s.envelope_sha256
     OR dr.readback_byte_length<>s.envelope_byte_length OR sr.readback_byte_length<>s.envelope_byte_length
     OR ar.drive_receipt_id<>dr.receipt_id OR ar.supabase_receipt_id<>sr.receipt_id OR ar.admission_receipt_id<>ae.event_id
     OR ar.original_source_locator<>s.source_locator
     OR ar.original_sha256<>s.original_sha256 OR ar.archive_member_sha256<>s.original_sha256
     OR ar.extracted_readback_sha256<>s.original_sha256 OR ar.extracted_readback_byte_length<>s.original_byte_length THEN
    RETURN pg_catalog.jsonb_build_object('status','CONFLICT','reason','FINALIZATION_EVIDENCE_NOT_EXACT');
  END IF;

  -- Chosen provider receipts must be the latest observed receipts for their provider classes in this attempt.
  IF EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_provider_receipts_v1 x
    WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class=dr.provider_class
      AND x.observation_ordinal > dr.observation_ordinal
  ) OR EXISTS (
    SELECT 1 FROM public.vera_memory_epoch_provider_receipts_v1 x
    WHERE x.subject_id=s.subject_id AND x.attempt_id=p_attempt_id AND x.provider_class=sr.provider_class
      AND x.observation_ordinal > sr.observation_ordinal
  ) THEN
    RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','STALE_PROVIDER_RECEIPT_SELECTION');
  END IF;

  next_version := s.state_version + 1;
  UPDATE public.vera_memory_epoch_subjects_v1
    SET state='R9B0_VERIFIED_ACTIVE',state_version=next_version,updated_at=pg_catalog.clock_timestamp()
    WHERE subject_id=p_subject_id AND state_version=p_expected_state_version AND state=p_expected_prior_state;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('status','CAS_CONFLICT','reason','LOST_UPDATE'); END IF;

  INSERT INTO public.vera_memory_epoch_events_v1(
    event_id,subject_id,state_version,prior_state,new_state,attempt_id,operation_id,event_kind,
    expected_state_version,envelope_sha256,event_payload
  ) VALUES (
    p_event_id,p_subject_id,next_version,p_expected_prior_state,'R9B0_VERIFIED_ACTIVE',p_attempt_id,p_operation_id,'FINALIZE',
    p_expected_state_version,s.envelope_sha256,
    (COALESCE(p_event_payload,'{}'::jsonb) - 'replay_binding' - 'diagnostic_nonbinding_fields') || pg_catalog.jsonb_build_object(
      'admission_receipt_id',p_admission_receipt_id,'drive_receipt_id',p_drive_receipt_id,
      'supabase_receipt_id',p_supabase_receipt_id,'archive_receipt_id',p_archive_receipt_id,
      'present_truth_promoted',false,'replay_binding',replay_binding,
      'diagnostic_nonbinding_fields',pg_catalog.jsonb_build_array('p_event_payload')
    )
  );

  RETURN pg_catalog.jsonb_build_object('status','APPLIED','event_id',p_event_id,'state','R9B0_VERIFIED_ACTIVE','state_version',next_version,'present_truth_promoted',false);
END
$fn$;

ALTER FUNCTION public._vera_memory_epoch_guard_v1() OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_get_status_v1(text,text,uuid,text) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_resume_incomplete_v1(text,text,uuid,text) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_begin_revalidation_v1(uuid,text,text,uuid,text,text,bigint,uuid,text,text,text,text,text,bigint,text,text,text,jsonb,uuid) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_record_admission_v1(uuid,text,bigint,uuid,text,boolean,text,text,text,bigint,uuid,jsonb) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_write_supabase_replica_v1(uuid,text,bigint,uuid,text,text,bytea,uuid,jsonb) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_record_archive_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,timestamptz,text,uuid,uuid,uuid,text,jsonb) OWNER TO postgres;
ALTER FUNCTION public.vera_memory_epoch_finalize_v1(uuid,text,bigint,uuid,text,uuid,uuid,uuid,uuid,uuid,jsonb) OWNER TO postgres;

REVOKE ALL ON FUNCTION public._vera_memory_epoch_guard_v1() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_get_status_v1(text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_resume_incomplete_v1(text,text,uuid,text) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_begin_revalidation_v1(uuid,text,text,uuid,text,text,bigint,uuid,text,text,text,text,text,bigint,text,text,text,jsonb,uuid) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_admission_v1(uuid,text,bigint,uuid,text,boolean,text,text,text,bigint,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_write_supabase_replica_v1(uuid,text,bigint,uuid,text,text,bytea,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_provider_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,bigint,timestamptz,timestamptz,bigint,text,text,text,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_record_archive_readback_v1(uuid,uuid,text,bigint,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,timestamptz,text,uuid,uuid,uuid,text,jsonb) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.vera_memory_epoch_finalize_v1(uuid,text,bigint,uuid,text,uuid,uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC, anon, authenticated, service_role;

COMMENT ON TABLE public.vera_memory_epoch_subjects_v1 IS 'R9B0 current state projection; full Supabase envelope bytes are stored here. Custody/admission does not imply present truth.';
COMMENT ON TABLE public.vera_memory_epoch_events_v1 IS 'Append-only R9B0 transition/admission/effect evidence. No public or service-role raw DML.';
COMMENT ON TABLE public.vera_memory_epoch_provider_receipts_v1 IS 'Append-only provider-specific readback evidence for SUPABASE_RUNTIME and GOOGLE_DRIVE_DURABLE. observation_ordinal is DB-assigned monotonic authority for provider-observation ordering; readback_time is provenance metadata only.';
COMMENT ON TABLE public.vera_memory_epoch_archive_receipts_v1 IS 'Append-only lossless original archive readback evidence, chained to admission and both provider receipts.';

-- Deliberately absent: vera_memory_epoch_resolve_conflict_v1.
-- MIGRATION_CONFLICTED is fail-closed until a separately reviewed predecessor-bound resolver exists.
