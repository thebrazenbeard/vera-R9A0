#!/usr/bin/env python3
"""Provider-free R9B0 Drive effect planner and exact-byte verifier.

This module never connects to Google Drive. It classifies already-observed provider
inventory, verifies downloaded bytes, and builds deterministic local archive bytes
for a separately authorized provider writer.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any, Iterable, Sequence

COMMANDS = (
    "inspect",
    "create-or-verify-active",
    "verify-active-readback",
    "create-or-verify-archive-generation",
    "verify-archive-readback",
)

ARCHIVE_SCHEMA = "R9B0_LOSSLESS_ARCHIVE_MEMBER_MANIFEST_V1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lp(value: str) -> bytes:
    raw = value.encode("utf-8")
    return len(raw).to_bytes(8, "big") + raw


def operation_identity(domain: str, fields: Sequence[str]) -> str:
    if not domain or any(not isinstance(x, str) for x in fields):
        raise ValueError("domain and all identity fields must be strings")
    material = _lp(domain) + len(fields).to_bytes(4, "big")
    material += b"".join(_lp(x) for x in fields)
    return sha256_bytes(material)


def _inventory_candidates(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if document is None:
        return []
    candidates = document.get("candidates", [])
    if not isinstance(candidates, list) or not all(isinstance(x, dict) for x in candidates):
        raise ValueError("inventory candidates must be a list of objects")
    return candidates


def classify_candidates(
    candidates: Sequence[dict[str, Any]],
    operation_id: str,
    expected_sha256: str,
    expected_byte_length: int,
) -> dict[str, Any]:
    bound = [c for c in candidates if c.get("operation_id") == operation_id]
    if not bound:
        return {
            "status": "CREATE",
            "operation_id": operation_id,
            "expected_sha256": expected_sha256,
            "expected_byte_length": expected_byte_length,
        }
    if len(bound) != 1:
        return {
            "status": "CONFLICT",
            "reason": "RESERVED_OPERATION_IDENTITY_MULTIPLE",
            "operation_id": operation_id,
            "candidate_count": len(bound),
        }
    candidate = bound[0]
    if (
        candidate.get("sha256") == expected_sha256
        and candidate.get("byte_length") == expected_byte_length
    ):
        return {
            "status": "VERIFIED_REUSE",
            "operation_id": operation_id,
            "provider_locator": candidate.get("provider_locator"),
            "sha256": expected_sha256,
            "byte_length": expected_byte_length,
        }
    return {
        "status": "CONFLICT",
        "reason": "RESERVED_OPERATION_IDENTITY_DIVERGENT",
        "operation_id": operation_id,
        "provider_locator": candidate.get("provider_locator"),
        "expected_sha256": expected_sha256,
        "observed_sha256": candidate.get("sha256"),
        "expected_byte_length": expected_byte_length,
        "observed_byte_length": candidate.get("byte_length"),
    }


def verify_exact_bytes(expected: bytes, readback: bytes) -> dict[str, Any]:
    expected_sha = sha256_bytes(expected)
    readback_sha = sha256_bytes(readback)
    exact = len(expected) == len(readback) and expected_sha == readback_sha and expected == readback
    return {
        "status": "VERIFIED_EXACT" if exact else "MISMATCH",
        "expected_byte_length": len(expected),
        "readback_byte_length": len(readback),
        "expected_sha256": expected_sha,
        "readback_sha256": readback_sha,
    }


def validate_archive_member_path(path: str) -> str:
    p = PurePosixPath(path)
    if not path or p.is_absolute() or ".." in p.parts or "." in p.parts or "\\" in path:
        raise ValueError("unsafe archive member path")
    normalized = str(p)
    if normalized.startswith("/") or normalized != path:
        raise ValueError("non-canonical archive member path")
    return normalized


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    validate_archive_member_path(name)
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def build_archive_generation(
    *,
    logical_memory_id: str,
    original_bytes: bytes,
    original_sha256: str,
    generation_id: str,
    predecessor_generation: str,
    predecessor_container_sha256: str,
    subject_id: str,
    admission_receipt_id: str,
    supabase_receipt_id: str,
    drive_receipt_id: str,
    operation_id: str,
) -> bytes:
    actual_sha = sha256_bytes(original_bytes)
    if actual_sha != original_sha256:
        raise ValueError("original bytes do not match original_sha256")
    if not generation_id or not logical_memory_id:
        raise ValueError("generation and logical memory identity are required")
    base = f"memories/{logical_memory_id}/{original_sha256}"
    original_path = validate_archive_member_path(f"{base}/original.bin")
    manifest_path = validate_archive_member_path(f"{base}/manifest.json")
    manifest = {
        "schema": ARCHIVE_SCHEMA,
        "generation_id": generation_id,
        "predecessor_generation": predecessor_generation,
        "predecessor_container_sha256": predecessor_container_sha256,
        "subject_id": subject_id,
        "logical_memory_id": logical_memory_id,
        "original_sha256": original_sha256,
        "original_byte_length": len(original_bytes),
        "archive_member_path": original_path,
        "archive_member_sha256": original_sha256,
        "admission_receipt_id": admission_receipt_id,
        "supabase_receipt_id": supabase_receipt_id,
        "drive_receipt_id": drive_receipt_id,
        "operation_id": operation_id,
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        tf.addfile(_tarinfo(original_path, len(original_bytes)), io.BytesIO(original_bytes))
        tf.addfile(_tarinfo(manifest_path, len(manifest_bytes)), io.BytesIO(manifest_bytes))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw_tar.getvalue())
    return out.getvalue()


def verify_archive_generation(
    archive_bytes: bytes,
    *,
    logical_memory_id: str,
    original_sha256: str,
    expected_original: bytes,
) -> dict[str, Any]:
    base = f"memories/{logical_memory_id}/{original_sha256}"
    original_path = validate_archive_member_path(f"{base}/original.bin")
    manifest_path = validate_archive_member_path(f"{base}/manifest.json")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            names = tf.getnames()
            for name in names:
                validate_archive_member_path(name)
            if sorted(names) != sorted([original_path, manifest_path]):
                return {"status": "MISMATCH", "reason": "ARCHIVE_MEMBER_SET_MISMATCH", "members": names}
            original_member = tf.extractfile(original_path)
            manifest_member = tf.extractfile(manifest_path)
            if original_member is None or manifest_member is None:
                return {"status": "MISMATCH", "reason": "ARCHIVE_MEMBER_UNREADABLE"}
            extracted = original_member.read()
            manifest = json.loads(manifest_member.read().decode("utf-8"))
    except (tarfile.TarError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {"status": "MISMATCH", "reason": "ARCHIVE_PARSE_FAILURE", "detail": type(exc).__name__}
    exact = verify_exact_bytes(expected_original, extracted)
    if exact["status"] != "VERIFIED_EXACT":
        return {"status": "MISMATCH", "reason": "ORIGINAL_READBACK_MISMATCH", **exact}
    if (
        manifest.get("schema") != ARCHIVE_SCHEMA
        or manifest.get("logical_memory_id") != logical_memory_id
        or manifest.get("original_sha256") != original_sha256
        or manifest.get("original_byte_length") != len(expected_original)
        or manifest.get("archive_member_sha256") != original_sha256
        or manifest.get("archive_member_path") != original_path
    ):
        return {"status": "MISMATCH", "reason": "ARCHIVE_MANIFEST_CROSSBIND_MISMATCH"}
    return {
        "status": "VERIFIED_EXACT",
        "archive_container_sha256": sha256_bytes(archive_bytes),
        "archive_byte_length": len(archive_bytes),
        "original_sha256": original_sha256,
        "original_byte_length": len(expected_original),
        "archive_member_path": original_path,
    }


def _load_json(path: str | None) -> dict[str, Any]:
    if path is None:
        return {"candidates": []}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def _print(result: dict[str, Any]) -> int:
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") not in {"CONFLICT", "MISMATCH"} else 2


def _active_plan(args: argparse.Namespace) -> dict[str, Any]:
    envelope = Path(args.envelope).read_bytes()
    envelope_sha = sha256_bytes(envelope)
    op = args.operation_id or operation_identity(
        "R9B0_PROVIDER_EFFECT_V1",
        [args.migration_key, "GOOGLE_DRIVE_DURABLE", envelope_sha],
    )
    result = classify_candidates(
        _inventory_candidates(_load_json(args.inventory)),
        op,
        envelope_sha,
        len(envelope),
    )
    result.update(
        {
            "provider_effect_performed": False,
            "relative_path": (
                f"active/{args.project_id}/{args.branch_id}/"
                f"{args.logical_memory_id}/{envelope_sha}.memory-epoch.json"
            ),
        }
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--inventory", required=True)
    inspect.add_argument("--operation-id", required=True)
    inspect.add_argument("--expected-sha256", required=True)
    inspect.add_argument("--expected-byte-length", type=int, required=True)

    active = sub.add_parser("create-or-verify-active")
    active.add_argument("--envelope", required=True)
    active.add_argument("--inventory")
    active.add_argument("--operation-id")
    active.add_argument("--migration-key", required=True)
    active.add_argument("--project-id", required=True)
    active.add_argument("--branch-id", required=True)
    active.add_argument("--logical-memory-id", required=True)

    active_read = sub.add_parser("verify-active-readback")
    active_read.add_argument("--expected", required=True)
    active_read.add_argument("--readback", required=True)

    archive = sub.add_parser("create-or-verify-archive-generation")
    archive.add_argument("--original", required=True)
    archive.add_argument("--output", required=True)
    archive.add_argument("--logical-memory-id", required=True)
    archive.add_argument("--original-sha256", required=True)
    archive.add_argument("--generation-id", required=True)
    archive.add_argument("--predecessor-generation", required=True)
    archive.add_argument("--predecessor-container-sha256", required=True)
    archive.add_argument("--subject-id", required=True)
    archive.add_argument("--admission-receipt-id", required=True)
    archive.add_argument("--supabase-receipt-id", required=True)
    archive.add_argument("--drive-receipt-id", required=True)
    archive.add_argument("--operation-id", required=True)

    archive_read = sub.add_parser("verify-archive-readback")
    archive_read.add_argument("--archive", required=True)
    archive_read.add_argument("--original", required=True)
    archive_read.add_argument("--logical-memory-id", required=True)
    archive_read.add_argument("--original-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect":
        return _print(
            classify_candidates(
                _inventory_candidates(_load_json(args.inventory)),
                args.operation_id,
                args.expected_sha256,
                args.expected_byte_length,
            )
        )
    if args.command == "create-or-verify-active":
        return _print(_active_plan(args))
    if args.command == "verify-active-readback":
        return _print(verify_exact_bytes(Path(args.expected).read_bytes(), Path(args.readback).read_bytes()))
    if args.command == "create-or-verify-archive-generation":
        original = Path(args.original).read_bytes()
        archive = build_archive_generation(
            logical_memory_id=args.logical_memory_id,
            original_bytes=original,
            original_sha256=args.original_sha256,
            generation_id=args.generation_id,
            predecessor_generation=args.predecessor_generation,
            predecessor_container_sha256=args.predecessor_container_sha256,
            subject_id=args.subject_id,
            admission_receipt_id=args.admission_receipt_id,
            supabase_receipt_id=args.supabase_receipt_id,
            drive_receipt_id=args.drive_receipt_id,
            operation_id=args.operation_id,
        )
        out = Path(args.output)
        if out.exists() and out.read_bytes() != archive:
            return _print({"status": "CONFLICT", "reason": "LOCAL_ARCHIVE_PATH_DIVERGENT"})
        if not out.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(archive)
        return _print(
            {
                "status": "VERIFIED_REUSE" if out.read_bytes() == archive else "CONFLICT",
                "provider_effect_performed": False,
                "archive_container_sha256": sha256_bytes(archive),
                "archive_byte_length": len(archive),
            }
        )
    if args.command == "verify-archive-readback":
        return _print(
            verify_archive_generation(
                Path(args.archive).read_bytes(),
                logical_memory_id=args.logical_memory_id,
                original_sha256=args.original_sha256,
                expected_original=Path(args.original).read_bytes(),
            )
        )
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
