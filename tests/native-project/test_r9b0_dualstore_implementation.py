from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "r9b0_memory_epoch_drive.py"
MIGRATION = ROOT / "supabase" / "migrations" / "20260822153000_r9b0_memory_epoch_v1.sql"
ROLLBACK = ROOT / "supabase" / "rollbacks" / "20260822153000_r9b0_memory_epoch_v1.sql"
SQL_TEST = ROOT / "supabase" / "tests" / "r9b0_memory_epoch_v1.sql"
LEDGER = ROOT / "supabase" / "MIGRATION_LEDGER.json"

EXPECTED_COMMANDS = {
    "inspect",
    "create-or-verify-active",
    "verify-active-readback",
    "create-or-verify-archive-generation",
    "verify-archive-readback",
}
EXPECTED_RPCS = {
    "vera_memory_epoch_get_status_v1",
    "vera_memory_epoch_resume_incomplete_v1",
    "vera_memory_epoch_begin_revalidation_v1",
    "vera_memory_epoch_record_admission_v1",
    "vera_memory_epoch_write_supabase_replica_v1",
    "vera_memory_epoch_record_provider_readback_v1",
    "vera_memory_epoch_record_archive_readback_v1",
    "vera_memory_epoch_finalize_v1",
}
FIXTURE_MARKER = "BT2_R9B0_DISPOSABLE_347D_PREDECESSOR_V1"


def load_helper():
    spec = importlib.util.spec_from_file_location("r9b0_memory_epoch_drive", HELPER)
    if spec is None or spec.loader is None:
        raise AssertionError("helper import spec unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestR9B0DualStoreImplementation(unittest.TestCase):
    def test_helper_exists_and_exports_exact_safe_command_surface(self):
        self.assertTrue(HELPER.is_file())
        mod = load_helper()
        self.assertEqual(set(mod.COMMANDS), EXPECTED_COMMANDS)
        source = HELPER.read_text(encoding="utf-8")
        for forbidden in (
            "import requests", "import httpx", "urllib.request", "googleapiclient",
            "google.auth", "import supabase", "import boto3",
        ):
            self.assertNotIn(forbidden, source.lower())
        for command in EXPECTED_COMMANDS:
            self.assertIn(command, source)

    def test_operation_identity_is_length_prefixed_deterministic_and_domain_bound(self):
        mod = load_helper()
        a = mod.operation_identity("R9B0_PROVIDER_EFFECT_V1", ["alpha", "b"])
        b = mod.operation_identity("R9B0_PROVIDER_EFFECT_V1", ["alpha", "b"])
        c = mod.operation_identity("R9B0_PROVIDER_EFFECT_V1", ["a", "lphab"])
        d = mod.operation_identity("R9B0_ARCHIVE_EFFECT_V1", ["alpha", "b"])
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertNotEqual(a, d)
        self.assertRegex(a, r"^[0-9a-f]{64}$")

    def test_create_or_verify_active_is_fail_closed_for_duplicate_or_divergent_identity(self):
        mod = load_helper()
        payload = b'{"schema":"MemoryEpochEnvelopeV1","x":1}'
        sha = hashlib.sha256(payload).hexdigest()
        op = mod.operation_identity("R9B0_PROVIDER_EFFECT_V1", ["m", "GOOGLE_DRIVE_DURABLE", sha])
        self.assertEqual(mod.classify_candidates([], op, sha, len(payload))["status"], "CREATE")
        exact = [{"operation_id": op, "sha256": sha, "byte_length": len(payload), "provider_locator": "file-1"}]
        self.assertEqual(mod.classify_candidates(exact, op, sha, len(payload))["status"], "VERIFIED_REUSE")
        divergent = [{"operation_id": op, "sha256": "0"*64, "byte_length": len(payload), "provider_locator": "file-1"}]
        self.assertEqual(mod.classify_candidates(divergent, op, sha, len(payload))["status"], "CONFLICT")
        self.assertEqual(mod.classify_candidates(exact + exact, op, sha, len(payload))["status"], "CONFLICT")

    def test_exact_readback_requires_byte_identity_not_metadata_claim(self):
        mod = load_helper()
        expected = b"canonical-envelope"
        self.assertEqual(mod.verify_exact_bytes(expected, expected)["status"], "VERIFIED_EXACT")
        result = mod.verify_exact_bytes(expected, b"canonical-envelopf")
        self.assertEqual(result["status"], "MISMATCH")
        self.assertNotEqual(result["expected_sha256"], result["readback_sha256"])

    def test_archive_generation_is_deterministic_lossless_and_traversal_safe(self):
        mod = load_helper()
        original = b"\x00original pre-r9b0 bytes\xff"
        kwargs = dict(
            logical_memory_id="70000000-0000-4000-8000-000000000002",
            original_bytes=original,
            original_sha256=hashlib.sha256(original).hexdigest(),
            generation_id="gen-001",
            predecessor_generation="gen-000",
            predecessor_container_sha256="1"*64,
            subject_id="70000000-0000-4000-8000-000000000001",
            admission_receipt_id="70000000-0000-4000-8000-000000000005",
            supabase_receipt_id="70000000-0000-4000-8000-000000000007",
            drive_receipt_id="70000000-0000-4000-8000-000000000009",
            operation_id="op-archive",
        )
        a = mod.build_archive_generation(**kwargs)
        b = mod.build_archive_generation(**kwargs)
        self.assertEqual(a, b)
        check = mod.verify_archive_generation(
            a,
            logical_memory_id=kwargs["logical_memory_id"],
            original_sha256=kwargs["original_sha256"],
            expected_original=original,
        )
        self.assertEqual(check["status"], "VERIFIED_EXACT")
        with self.assertRaises(ValueError):
            mod.validate_archive_member_path("../escape")

    def test_db_g5_portable_invariants_and_locator_crossbind_are_present(self):
        migration = MIGRATION.read_text(encoding="utf-8")
        sql_test = SQL_TEST.read_text(encoding="utf-8")
        combined = migration + "\n" + sql_test
        self.assertNotIn("supabase_migrations.schema_migrations", combined)
        self.assertNotRegex(migration, r"(?i)\bc\.oid\s*=\s*\d+")
        self.assertNotRegex(migration, r"(?i)\boid\s+IN\s*\([^)]*\d")
        for rel in (
            "vera_verified_datum_heads_v2",
            "vera_active_datum_index_v2",
            "vera_inactive_datum_archive_v2",
            "vera_current_context_v3",
        ):
            self.assertIn(rel, migration)
        self.assertIn(FIXTURE_MARKER, sql_test)
        self.assertIn("ARCHIVE_SOURCE_LOCATOR_MISMATCH", migration)
        self.assertIn("ar.original_source_locator<>s.source_locator", migration.replace(" ", ""))
        self.assertIn("'original_source_locator',s.source_locator", migration.replace(" ", ""))

    def test_db_surface_is_exact_eight_public_rpcs_no_resolver_and_nondestructive_rollback(self):
        migration = MIGRATION.read_text(encoding="utf-8")
        rollback = ROLLBACK.read_text(encoding="utf-8")
        created = {
            m.group(1)
            for m in __import__("re").finditer(
                r"CREATE FUNCTION public\.([a-z0-9_]+)\s*\(", migration, __import__("re").I
            )
            if not m.group(1).startswith("_")
        }
        self.assertEqual(created, EXPECTED_RPCS)
        self.assertNotRegex(
            migration,
            r"(?i)CREATE\s+FUNCTION\s+public\.vera_memory_epoch_resolve_conflict_v1\s*\(",
        )
        lower = rollback.lower()
        self.assertNotIn("drop table", lower)
        self.assertNotIn("truncate", lower)
        self.assertNotIn("delete from", lower)
        self.assertIn("revoke", lower)

    def test_g1_workflow_is_provider_free_and_binds_exact_commit_and_fixture(self):
        workflow = (ROOT / ".github" / "workflows" / "r9b0-memory-epoch.yml").read_text(encoding="utf-8")
        self.assertIn("postgres:15", workflow)
        self.assertIn(FIXTURE_MARKER, workflow)
        self.assertIn("github.sha", workflow)
        self.assertIn("hosted_supabase_apply_performed", workflow)
        self.assertIn("drive_effect_performed", workflow)
        self.assertNotIn("klmbpaigzeguvnpccqzz", workflow)
        self.assertNotIn("supabase_migrations.schema_migrations", workflow)
        self.assertNotIn("bt2_347d_vera_view_hardening_v1", workflow)
        self.assertNotIn("SUPABASE_ACCESS_TOKEN", workflow)
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", workflow)
        for rel in (
            "supabase/migrations/20260822153000_r9b0_memory_epoch_v1.sql",
            "supabase/tests/r9b0_memory_epoch_v1.sql",
            "scripts/r9b0_memory_epoch_drive.py",
            "tests/native-project/test_r9b0_dualstore_implementation.py",
        ):
            self.assertIn(rel, workflow)

    def test_ledger_is_candidate_not_false_applied_claim(self):
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        items = [x for x in ledger["migrations"] if x.get("source_version") == "20260822153000"]
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["status"], "CANDIDATE_G0_NOT_APPLIED")
        self.assertIsNone(item["applied_version"])
        self.assertIsNone(item["applied_commit"])
        self.assertEqual(item["target_project_ref"], "klmbpaigzeguvnpccqzz")
        self.assertEqual(
            item["source_sha256"],
            hashlib.sha256(MIGRATION.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            item["test_sha256"],
            hashlib.sha256(SQL_TEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            item["rollback_sha256"],
            hashlib.sha256(ROLLBACK.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
