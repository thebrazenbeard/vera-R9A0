#!/usr/bin/env python3
"""Provider-free R9B0 Drive effect planner and bounded exact-byte verifier."""
from __future__ import annotations
import argparse, base64, datetime as dt, errno, gzip, hashlib, io, json, math, os, stat, tarfile, unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Sequence

COMMANDS=("inspect","create-or-verify-active","verify-active-readback","create-or-verify-archive-generation","verify-archive-readback")
ARCHIVE_SCHEMA="R9B0_LOSSLESS_ARCHIVE_MEMBER_MANIFEST_V1"
MEMORY_EPOCH_OPERATION_DOMAIN="R9B0_MEMORY_EPOCH_OPERATION_V1"
ENVELOPE_SCHEMA="MemoryEpochEnvelopeV1"
ENVELOPE_VERSION="1.0.1"
INVENTORY_SNAPSHOT_SCHEMA="R9B0_DRIVE_INVENTORY_SNAPSHOT_V1"
PROVIDER_READBACK_EVIDENCE_SCHEMA="R9B0_PROVIDER_READBACK_EVIDENCE_V1"
ARCHIVE_READBACK_EVIDENCE_SCHEMA="R9B0_ARCHIVE_READBACK_EVIDENCE_V1"
EVIDENCE_ATTESTATION_SCHEMA="R9B0_VERIFIER_AUTHORITY_ATTESTATION_V1"
ADMISSION_EVIDENCE_SCHEMA="R9B0_ACTIVE_DUPLICATION_ADMISSION_EVIDENCE_V1"
ACTIVE_STORE_READBACK_EVIDENCE_SCHEMA="R9B0_ACTIVE_STORE_READBACK_EVIDENCE_V1"
ACTIVE_STORE_READBACK_ROLE_BY_PURPOSE={"ACTIVE_STORE_READBACK_SUPABASE":"SUPABASE_RUNTIME","ACTIVE_STORE_READBACK_DRIVE":"GOOGLE_DRIVE_DURABLE"}
# Detached evidence is authority-bearing.  This bounded helper may VERIFY a
# separately governed verifier root, but it may not create/select credentials.
# No current project-owned verifier key binding was present in the reviewed
# source set, so production stays fail-closed until Architect/user authority
# supplies an exact reviewed public-key binding in a later authorized change.
EVIDENCE_TRUST_ROOT_STATE="UNCONFIGURED"
EVIDENCE_AUTHORITY_ID="UNCONFIGURED"
EVIDENCE_KEY_ID="UNCONFIGURED"
_EVIDENCE_RSA_N=None
_EVIDENCE_RSA_E=65537
MAX_EVIDENCE_AGE_SECONDS=300
RESOURCE_PROFILE_SCHEMA="MEMORY_EPOCH_RESOURCE_PROFILE_V1"
RESOURCE_PROFILE_BINDING_SCHEMA="MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT_BINDING_V1"
RESOURCE_PROFILE_REQUIRED_FIELDS=("max_source_bytes","max_decoded_bytes","max_envelope_bytes","max_archive_member_expanded_bytes","max_archive_generation_expanded_bytes","max_expansion_ratio","stream_chunk_bytes")
RESOURCE_BYTE_LIMIT_FIELDS=("max_source_bytes","max_decoded_bytes","max_envelope_bytes","max_archive_member_expanded_bytes","max_archive_generation_expanded_bytes")
RESOURCE_LIMIT_REASON_BY_FIELD={"max_source_bytes":"SOURCE_BYTES_EXCEEDED","max_decoded_bytes":"BYTE_LIMIT_EXCEEDED","max_envelope_bytes":"ENVELOPE_BYTES_EXCEEDED","max_archive_member_expanded_bytes":"ARCHIVE_MEMBER_BYTES_EXCEEDED","max_archive_generation_expanded_bytes":"ARCHIVE_GENERATION_BYTES_EXCEEDED"}
VERIFY_STREAM_RESOURCE_FIELDS=("max_decoded_bytes","max_envelope_bytes")
R9B0_DRIVE_PARENT_ID="1aXy_yUUm-EA-mkEiAuuAGq8iLJdPnQY3"
ARCHIVE_PROVENANCE_FIELDS=("generation_id","predecessor_generation","predecessor_container_sha256","subject_id","admission_receipt_id","supabase_receipt_id","drive_receipt_id","operation_id")
_RESOURCE_PROFILE_V2={"schema":RESOURCE_PROFILE_SCHEMA,"profile_id":"R9B0_RESOURCE_PROFILE_2026_08_24_V2","max_source_bytes":67108864,"max_decoded_bytes":100663296,"max_envelope_bytes":100663296,"max_archive_member_expanded_bytes":67108864,"max_archive_generation_expanded_bytes":134217728,"max_expansion_ratio":32.0,"stream_chunk_bytes":65536}

def resource_profile_sha256(profile):
    return hashlib.sha256(json.dumps(profile,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()

RESOURCE_PROFILE_REGISTRY={_RESOURCE_PROFILE_V2["profile_id"]:_RESOURCE_PROFILE_V2}
MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT={"schema":RESOURCE_PROFILE_BINDING_SCHEMA,"profile_id":_RESOURCE_PROFILE_V2["profile_id"],"profile_sha256":resource_profile_sha256(_RESOURCE_PROFILE_V2)}

class ResourceBlocked(RuntimeError):
    def __init__(self,status,reason,*,observed=None,limit=None):
        super().__init__(reason); self.status=status; self.reason=reason; self.observed=observed; self.limit=limit
    def as_result(self):
        r={"status":self.status,"reason":self.reason}
        if self.observed is not None:r["observed"]=self.observed
        if self.limit is not None:r["limit"]=self.limit
        return r

def sha256_bytes(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def _lp(value:str)->bytes:
    raw=value.encode(); return len(raw).to_bytes(8,"big")+raw

def operation_identity(domain:str,fields:Sequence[str])->str:
    if not domain or any(not isinstance(x,str) for x in fields): raise ValueError("domain and all identity fields must be strings")
    return sha256_bytes(_lp(domain)+len(fields).to_bytes(4,"big")+b"".join(_lp(x) for x in fields))

def memory_epoch_operation_identity(fields:Sequence[str])->str:
    if len(fields)!=7 or any(not isinstance(x,str) or not x for x in fields): raise ValueError("memory epoch operation identity requires exactly seven nonempty UTF-8 fields")
    return sha256_bytes(len(fields).to_bytes(4,"big")+b"".join(_lp(x) for x in fields))


def _reject_duplicate_pairs(pairs):
    out={}
    for key,value in pairs:
        if key in out: raise ValueError(f"duplicate JSON key: {key}")
        out[key]=value
    return out

def _reject_nonfinite(value):
    raise ValueError(f"nonfinite JSON number: {value}")

def strict_json_loads(raw):
    if isinstance(raw,bytes):
        try: text=raw.decode("utf-8")
        except UnicodeDecodeError as exc: raise ValueError("JSON must be UTF-8") from exc
    elif isinstance(raw,str): text=raw
    else: raise ValueError("JSON input must be bytes or string")
    try: return json.loads(text,object_pairs_hook=_reject_duplicate_pairs,parse_constant=_reject_nonfinite)
    except json.JSONDecodeError as exc: raise ValueError("invalid JSON") from exc

def _canonical_json_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")

def _require_exact_keys(obj,required,*,optional=(),name="object"):
    if not isinstance(obj,dict): raise ValueError(f"{name} must be an object")
    req=set(required); allowed=req|set(optional); missing=req-set(obj); extra=set(obj)-allowed
    if missing or extra: raise ValueError(f"{name} keyset mismatch: missing={sorted(missing)} extra={sorted(extra)}")

def _require_str(value,name,*,nonempty=True):
    if not isinstance(value,str) or (nonempty and not value): raise ValueError(f"{name} must be a nonempty string")
    return value

def _require_str_list(value,name):
    if not isinstance(value,list) or any(not isinstance(x,str) for x in value): raise ValueError(f"{name} must be an array of strings")
    return value

def _require_int(value,name,*,minimum=0):
    if isinstance(value,bool) or not isinstance(value,int) or value<minimum: raise ValueError(f"{name} must be an integer >= {minimum}")
    return value

def _digest_document(document,digest_field):
    body=dict(document); body.pop(digest_field,None); return sha256_bytes(_canonical_json_bytes(body))

def _validate_document_digest(document,digest_field):
    supplied=validate_sha256_hex(document.get(digest_field),digest_field)
    if supplied!=_digest_document(document,digest_field): raise ValueError(f"{digest_field} mismatch")
    return supplied

def _parse_utc(value,name):
    _require_str(value,name)
    try:
        parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc: raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None: raise ValueError(f"{name} must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc)

def _validate_current_observation(observed_at,*,valid_until=None,now=None):
    now=(now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    observed=_parse_utc(observed_at,"observed_at")
    if observed>now+dt.timedelta(seconds=5): raise ValueError("observation is from the future")
    if valid_until is None:
        if now-observed>dt.timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS): raise ValueError("observation is stale")
        return observed
    until=_parse_utc(valid_until,"valid_until")
    if until<observed: raise ValueError("valid_until precedes observed_at")
    if until-observed>dt.timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS): raise ValueError("evidence validity window is too long")
    if now>until: raise ValueError("evidence validity window expired")
    return observed


def _canonical_b64_decode(value,name):
    _require_str(value,name)
    try: raw=base64.b64decode(value,validate=True)
    except Exception as exc: raise ValueError(f"{name} invalid base64") from exc
    if base64.b64encode(raw).decode("ascii")!=value: raise ValueError(f"{name} is not canonical RFC4648 base64")
    return raw

def verifier_trust_root_configured():
    return EVIDENCE_TRUST_ROOT_STATE=="CONFIGURED" and isinstance(_EVIDENCE_RSA_N,int) and _EVIDENCE_RSA_N>0

def _verify_rsa_pkcs1v15_sha256(message,signature_b64):
    if not verifier_trust_root_configured():
        raise ValueError("verifier trust root is not configured")
    sig=_canonical_b64_decode(signature_b64,"signature_base64")
    k=(_EVIDENCE_RSA_N.bit_length()+7)//8
    if len(sig)!=k: raise ValueError("authority signature length mismatch")
    em=pow(int.from_bytes(sig,"big"),_EVIDENCE_RSA_E,_EVIDENCE_RSA_N).to_bytes(k,"big")
    digest=hashlib.sha256(message).digest()
    digest_info=bytes.fromhex("3031300d060960864801650304020105000420")+digest
    expected=b"\x00\x01"+b"\xff"*(k-len(digest_info)-3)+b"\x00"+digest_info
    if em!=expected: raise ValueError("authority signature verification failed")

def validate_authority_attestation(attestation,*,expected_evidence_sha256,expected_purpose):
    required=("schema","authority_id","key_id","purpose","evidence_sha256","issued_at","valid_until","nonce","signature_base64")
    _require_exact_keys(attestation,required,name="verifier authority attestation")
    if attestation["schema"]!=EVIDENCE_ATTESTATION_SCHEMA or attestation["authority_id"]!=EVIDENCE_AUTHORITY_ID or attestation["key_id"]!=EVIDENCE_KEY_ID: raise ValueError("untrusted verifier authority")
    if attestation["purpose"]!=expected_purpose: raise ValueError("authority attestation purpose mismatch")
    if attestation["evidence_sha256"]!=validate_sha256_hex(expected_evidence_sha256,"expected_evidence_sha256"): raise ValueError("authority attestation evidence digest mismatch")
    _require_str(attestation["nonce"],"nonce")
    _validate_current_observation(attestation["issued_at"],valid_until=attestation["valid_until"])
    body=dict(attestation); signature=body.pop("signature_base64")
    _verify_rsa_pkcs1v15_sha256(_canonical_json_bytes(body),signature)
    return attestation

def derive_memory_epoch_operation_id(envelope):
    return memory_epoch_operation_identity([
        envelope["epoch_id"],envelope["project_id"],envelope["branch_id"],envelope["logical_memory_id"],
        envelope["original"]["source_version_or_generation"],envelope["original"]["sha256"],envelope["migration"]["admission_generation"]
    ])

def _validate_unicode_nfc(value,path="$"):
    if isinstance(value,str):
        if unicodedata.normalize("NFC",value)!=value: raise ValueError(f"non-NFC Unicode at {path}")
    elif isinstance(value,list):
        for i,item in enumerate(value): _validate_unicode_nfc(item,f"{path}[{i}]")
    elif isinstance(value,dict):
        for key,item in value.items():
            _validate_unicode_nfc(key,f"{path}.<key>"); _validate_unicode_nfc(item,f"{path}.{key}")

def parse_memory_epoch_envelope(raw):
    obj=strict_json_loads(raw); _validate_unicode_nfc(obj)
    _require_exact_keys(obj,("schema","version","epoch_id","project_id","branch_id","logical_memory_id","memory_class","original","provenance","governance","indexing","migration"),name="MemoryEpochEnvelopeV1")
    if obj["schema"]!=ENVELOPE_SCHEMA or obj["version"]!=ENVELOPE_VERSION or obj["epoch_id"]!="R9B0": raise ValueError("envelope schema/version/epoch mismatch")
    validate_identity_segment(obj["project_id"],"project_id"); validate_identity_segment(obj["branch_id"],"branch_id"); validate_identity_segment(obj["logical_memory_id"],"logical_memory_id")
    if obj["memory_class"] not in {"AUTOBIOGRAPHICAL","WORKING_PROJECT","HISTORICAL_AUDIT"}: raise ValueError("memory_class invalid")
    original=obj["original"]; _require_exact_keys(original,("provider_class","source_locator","source_version_or_generation","record_identity","content_type","byte_length","sha256","bytes_base64"),name="original")
    for key in ("provider_class","source_locator","source_version_or_generation","record_identity","content_type"): _require_str(original[key],f"original.{key}")
    _require_int(original["byte_length"],"original.byte_length"); validate_sha256_hex(original["sha256"],"original.sha256"); _require_str(original["bytes_base64"],"original.bytes_base64",nonempty=False)
    original_bytes=_canonical_b64_decode(original["bytes_base64"],"original.bytes_base64")
    if len(original_bytes)!=original["byte_length"] or sha256_bytes(original_bytes)!=original["sha256"]: raise ValueError("original bytes identity mismatch")
    provenance=obj["provenance"]; _require_exact_keys(provenance,("source_actor","epistemic_class","source_evidence","event_time","record_time","state_time","retrieval_time","limitations"),name="provenance")
    _require_str(provenance["source_actor"],"provenance.source_actor"); _require_str(provenance["epistemic_class"],"provenance.epistemic_class"); _require_str_list(provenance["source_evidence"],"provenance.source_evidence"); _require_str_list(provenance["limitations"],"provenance.limitations")
    for key in ("event_time","record_time","state_time","retrieval_time"):
        if provenance[key] is not None and not isinstance(provenance[key],str): raise ValueError(f"provenance.{key} must be string or null")
    if provenance["retrieval_time"] is None and "RETRIEVAL_TIME_UNKNOWN" not in provenance["limitations"]: raise ValueError("null retrieval_time requires RETRIEVAL_TIME_UNKNOWN")
    governance=obj["governance"]; _require_exact_keys(governance,("privacy_scope","lifecycle","admission_authority_ref","contradiction_links","supersession_links","tombstone_links","currentness_rule"),name="governance")
    for key in ("privacy_scope","lifecycle","admission_authority_ref"): _require_str(governance[key],f"governance.{key}")
    for key in ("contradiction_links","supersession_links","tombstone_links"): _require_str_list(governance[key],f"governance.{key}")
    if governance["currentness_rule"] not in {"IMMUTABLE","REVALIDATE_ON_USE","SUPERSESSION_GRAPH"}: raise ValueError("governance.currentness_rule invalid")
    indexing=obj["indexing"]; _require_exact_keys(indexing,("semantic_keys","aliases","tags","relationships","literal_phrases","temporal_anchors"),name="indexing")
    for key in ("semantic_keys","aliases","tags","relationships","literal_phrases","temporal_anchors"): _require_str_list(indexing[key],f"indexing.{key}")
    migration=obj["migration"]; _require_exact_keys(migration,("operation_id","attempt_id","source_snapshot_digest","target_epoch","admission_generation","admission_metadata_sha256"),name="migration")
    _require_str(migration["operation_id"],"migration.operation_id"); _require_str(migration["attempt_id"],"migration.attempt_id"); validate_sha256_hex(migration["source_snapshot_digest"],"migration.source_snapshot_digest"); validate_sha256_hex(migration["admission_metadata_sha256"],"migration.admission_metadata_sha256"); _require_str(migration["admission_generation"],"migration.admission_generation")
    if migration["target_epoch"]!="R9B0": raise ValueError("migration.target_epoch invalid")
    canonical=_canonical_json_bytes(obj)
    if canonical!=raw: raise ValueError("envelope bytes are not canonical MemoryEpochEnvelopeV1 serialization")
    expected_operation_id=derive_memory_epoch_operation_id(obj)
    if migration["operation_id"]!=expected_operation_id: raise ValueError("migration.operation_id does not match canonical operation identity")
    return {"document":obj,"operation_id":expected_operation_id,"project_id":obj["project_id"],"branch_id":obj["branch_id"],"logical_memory_id":obj["logical_memory_id"],"original_sha256":original["sha256"],"original_byte_length":original["byte_length"],"original_bytes":original_bytes,"source_version_or_generation":original["source_version_or_generation"],"admission_generation":migration["admission_generation"]}

def _contains_disallowed_control(value:str)->bool:
    return any(unicodedata.category(ch) in {"Cc","Cf"} for ch in value)

def validate_identity_segment(value,name="identity"):
    if not isinstance(value,str) or not value or value in {".",".."} or "/" in value or "\\" in value or _contains_disallowed_control(value): raise ValueError(f"{name} must be one canonical nonempty segment")
    if len(PurePosixPath(value).parts)!=1 or str(PurePosixPath(value))!=value: raise ValueError(f"{name} must be one canonical nonempty segment")
    return value

def validate_sha256_hex(value,name="sha256"):
    if not isinstance(value,str) or len(value)!=64 or any(c not in "0123456789abcdef" for c in value): raise ValueError(f"{name} must be lowercase sha256 hex")
    return value

def _active_relative_path(project_id,branch_id,logical_memory_id,envelope_sha256):
    project_id=validate_identity_segment(project_id,"project_id"); branch_id=validate_identity_segment(branch_id,"branch_id"); logical_memory_id=validate_identity_segment(logical_memory_id,"logical_memory_id"); validate_sha256_hex(envelope_sha256,"envelope_sha256")
    return f"active/{project_id}/{branch_id}/{logical_memory_id}/{envelope_sha256}.memory-epoch.json"

def _archive_manifest_bytes(*,logical_memory_id,original_sha256,original_byte_length,generation_id,predecessor_generation,predecessor_container_sha256,subject_id,admission_receipt_id,supabase_receipt_id,drive_receipt_id,operation_id):
    logical_memory_id=validate_identity_segment(logical_memory_id,"logical_memory_id"); validate_sha256_hex(original_sha256,"original_sha256")
    if not isinstance(original_byte_length,int) or isinstance(original_byte_length,bool) or original_byte_length<0: raise ValueError("original_byte_length must be a nonnegative integer")
    manifest={"schema":ARCHIVE_SCHEMA,"generation_id":generation_id,"predecessor_generation":predecessor_generation,"predecessor_container_sha256":predecessor_container_sha256,"subject_id":subject_id,"logical_memory_id":logical_memory_id,"original_sha256":original_sha256,"original_byte_length":original_byte_length,"archive_member_path":f"memories/{logical_memory_id}/{original_sha256}/original.bin","archive_member_sha256":original_sha256,"admission_receipt_id":admission_receipt_id,"supabase_receipt_id":supabase_receipt_id,"drive_receipt_id":drive_receipt_id,"operation_id":operation_id}
    for key in ARCHIVE_PROVENANCE_FIELDS:
        if not isinstance(manifest[key],str) or not manifest[key]: raise ValueError(f"{key} must be a nonempty string")
    validate_sha256_hex(predecessor_container_sha256,"predecessor_container_sha256")
    manifest["archive_member_path"]=validate_archive_member_path(manifest["archive_member_path"])
    return (json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode()

def validate_resource_profile(profile):
    if not isinstance(profile,dict): raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_MISSING")
    if profile.get("schema")!=RESOURCE_PROFILE_SCHEMA: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_SCHEMA")
    if not isinstance(profile.get("profile_id"),str) or not profile["profile_id"]: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_ID")
    if "current" in profile: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_CURRENTNESS_SELF_DECLARED")
    for key in RESOURCE_PROFILE_REQUIRED_FIELDS:
        v=profile.get(key)
        if isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v) or v<=0: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE",f"RESOURCE_PROFILE_INVALID_{key.upper()}")
    if int(profile["stream_chunk_bytes"])!=profile["stream_chunk_bytes"]: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_CHUNK_NOT_INTEGER")
    if profile["max_archive_member_expanded_bytes"]>profile["max_archive_generation_expanded_bytes"]: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_INCONSISTENT_ARCHIVE_LIMITS")
    return profile

def resolve_current_resource_profile(binding=None):
    current_binding=MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT
    if binding is not None:
        if not isinstance(binding,dict) or binding.get("schema")!=RESOURCE_PROFILE_BINDING_SCHEMA: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_SCHEMA")
        if binding!=current_binding: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_OVERRIDE_NOT_CURRENT")
    b=current_binding
    if not isinstance(b,dict) or b.get("schema")!=RESOURCE_PROFILE_BINDING_SCHEMA: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_SCHEMA")
    profile_id=b.get("profile_id"); expected_sha=b.get("profile_sha256")
    if not isinstance(profile_id,str) or not profile_id or not isinstance(expected_sha,str) or len(expected_sha)!=64: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_INVALID")
    profile=RESOURCE_PROFILE_REGISTRY.get(profile_id)
    if profile is None: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_UNKNOWN")
    validate_resource_profile(profile)
    if resource_profile_sha256(profile)!=expected_sha: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_BINDING_DIGEST")
    return dict(profile)

def _effective_profile(profile):
    current=resolve_current_resource_profile()
    if profile is None:return current
    validate_resource_profile(profile)
    if profile.get("profile_id")!=current["profile_id"] or resource_profile_sha256(profile)!=resource_profile_sha256(current): raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_PROFILE_OVERRIDE_NOT_CURRENT")
    return current

def _limit_next(total,next_size,limit,reason):
    projected=total+next_size
    if projected>limit: raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT",reason,observed=projected,limit=limit)

def _ratio_limit(decoded,source,ratio):
    if source<=0:
        if decoded>0: raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","EXPANSION_RATIO_ZERO_SOURCE",observed=decoded,limit=0)
        return
    observed=decoded/source
    if observed>ratio: raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","EXPANSION_RATIO_EXCEEDED",observed=observed,limit=ratio)

def _resource_block_result(exc,*,after_possible_effect=False):
    return {"status":"MIGRATION_INCOMPLETE","reason":exc.reason} if after_possible_effect else exc.as_result()

def _profile_byte_limit(profile,field):
    if field not in RESOURCE_BYTE_LIMIT_FIELDS: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_LIMIT_FIELD_NOT_GOVERNED")
    return int(profile[field])

def _canonical_limit_reason(field):
    reason=RESOURCE_LIMIT_REASON_BY_FIELD.get(field)
    if reason is None: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_LIMIT_FIELD_NOT_GOVERNED")
    return reason

def _bounded_numeric_override(value,governed,invalid_reason):
    if value is None:return int(governed)
    if isinstance(value,bool) or not isinstance(value,int) or value<=0: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE",invalid_reason)
    return min(value,int(governed))

def _read_stream_bounded_raw(stream:BinaryIO,*,byte_limit:int,chunk_bytes:int,digest=None,limit_reason="BYTE_LIMIT_EXCEEDED")->bytes:
    out=io.BytesIO(); total=0
    while True:
        chunk=stream.read(chunk_bytes)
        if not chunk: break
        _limit_next(total,len(chunk),byte_limit,limit_reason); total+=len(chunk)
        if digest is not None:digest.update(chunk)
        out.write(chunk)
    return out.getvalue()

def _read_stream_profile_field(stream:BinaryIO,profile,field,*,digest=None)->bytes:
    return _read_stream_bounded_raw(stream,byte_limit=_profile_byte_limit(profile,field),chunk_bytes=int(profile["stream_chunk_bytes"]),digest=digest,limit_reason=_canonical_limit_reason(field))

def _read_path_profile_field(path:Path,profile,field)->bytes:
    with path.open("rb") as fh:return _read_stream_profile_field(fh,profile,field)

def read_stream_bounded(stream:BinaryIO,*,byte_limit=None,chunk_bytes=None,digest=None,limit_reason=None)->bytes:
    profile=resolve_current_resource_profile(); governed_limit=_profile_byte_limit(profile,"max_source_bytes"); governed_chunk=int(profile["stream_chunk_bytes"]); reason=_canonical_limit_reason("max_source_bytes")
    if limit_reason is not None and limit_reason!=reason: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_LIMIT_REASON_OVERRIDE_NOT_GOVERNED")
    effective_limit=_bounded_numeric_override(byte_limit,governed_limit,"RESOURCE_BYTE_LIMIT_OVERRIDE_INVALID"); effective_chunk=_bounded_numeric_override(chunk_bytes,governed_chunk,"RESOURCE_CHUNK_OVERRIDE_INVALID")
    return _read_stream_bounded_raw(stream,byte_limit=effective_limit,chunk_bytes=effective_chunk,digest=digest,limit_reason=reason)

def read_path_bounded(path:Path,*,byte_limit=None,chunk_bytes=None,limit_reason=None)->bytes:
    with path.open("rb") as fh:return read_stream_bounded(fh,byte_limit=byte_limit,chunk_bytes=chunk_bytes,limit_reason=limit_reason)

def validate_readback_evidence(evidence,*,operation_id=None,sha256=None,byte_length=None,provider_locator=None,provider_revision=None,parent_id=None,relative_path=None,expected_evidence_sha256=None):
    required=("schema","status","provider_class","provider_locator","provider_revision","operation_id","parent_id","relative_path","sha256","byte_length","receipt_id","observation_id","observed_at","currentness_status","verifier_route","evidence_sha256")
    _require_exact_keys(evidence,required,name="provider readback evidence")
    if evidence["schema"]!=PROVIDER_READBACK_EVIDENCE_SCHEMA or evidence["status"]!="VERIFIED_EXACT" or evidence["provider_class"]!="GOOGLE_DRIVE_DURABLE" or evidence["currentness_status"]!="VERIFIED_CURRENT": raise ValueError("provider readback evidence status/schema invalid")
    for key in ("provider_locator","provider_revision","operation_id","receipt_id","observation_id","verifier_route"): _require_str(evidence[key],key)
    validate_identity_segment(evidence["parent_id"],"parent_id"); validate_archive_member_path(evidence["relative_path"]); validate_sha256_hex(evidence["sha256"],"sha256"); _require_int(evidence["byte_length"],"byte_length")
    _validate_document_digest(evidence,"evidence_sha256")
    if expected_evidence_sha256 is not None and evidence["evidence_sha256"]!=validate_sha256_hex(expected_evidence_sha256,"expected_evidence_sha256"): raise ValueError("readback evidence digest does not match trusted receipt graph")
    _validate_current_observation(evidence["observed_at"])
    checks={"operation_id":operation_id,"sha256":sha256,"byte_length":byte_length,"provider_locator":provider_locator,"provider_revision":provider_revision,"parent_id":parent_id,"relative_path":relative_path}
    for key,expected in checks.items():
        if expected is not None and evidence[key]!=expected: raise ValueError(f"readback evidence {key} mismatch")
    return evidence


def validate_duplication_admission_evidence(evidence,attestation,*,parsed_envelope,envelope_sha256):
    required=("schema","status","operation_id","envelope_sha256","admission_authority_ref","admission_generation","admission_metadata_sha256","privacy_scope","lifecycle","duplication_eligible","receipt_id","observation_id","observed_at","valid_until","currentness_status","evidence_sha256")
    _require_exact_keys(evidence,required,name="active duplication admission evidence")
    if evidence["schema"]!=ADMISSION_EVIDENCE_SCHEMA or evidence["status"]!="VERIFIED_ELIGIBLE" or evidence["currentness_status"]!="VERIFIED_CURRENT": raise ValueError("admission evidence status/schema invalid")
    for key in ("operation_id","admission_authority_ref","admission_generation","privacy_scope","lifecycle","receipt_id","observation_id"): _require_str(evidence[key],key)
    validate_sha256_hex(evidence["envelope_sha256"],"envelope_sha256"); validate_sha256_hex(evidence["admission_metadata_sha256"],"admission_metadata_sha256")
    if evidence["duplication_eligible"] is not True: raise ValueError("duplication not eligible")
    document=parsed_envelope["document"]; governance=document["governance"]; migration=document["migration"]
    if governance["privacy_scope"]=="PRIVATE_FORBIDDEN_TO_DUPLICATE": raise ValueError("privacy scope forbids duplication")
    if governance["lifecycle"]=="TOMBSTONED": raise ValueError("lifecycle forbids duplication")
    checks={
        "operation_id":parsed_envelope["operation_id"],
        "envelope_sha256":envelope_sha256,
        "admission_authority_ref":governance["admission_authority_ref"],
        "admission_generation":migration["admission_generation"],
        "admission_metadata_sha256":migration["admission_metadata_sha256"],
        "privacy_scope":governance["privacy_scope"],
        "lifecycle":governance["lifecycle"],
    }
    for key,expected in checks.items():
        if evidence[key]!=expected: raise ValueError(f"admission evidence {key} mismatch")
    digest=_validate_document_digest(evidence,"evidence_sha256")
    _validate_current_observation(evidence["observed_at"],valid_until=evidence["valid_until"])
    validate_authority_attestation(attestation,expected_evidence_sha256=digest,expected_purpose="ACTIVE_DUPLICATION_ADMISSION")
    return evidence

def validate_active_store_readback_evidence(evidence,attestation,*,expected_purpose,operation_id,envelope_sha256,envelope_byte_length,project_id,branch_id,epoch_id,logical_memory_id,original_sha256,original_byte_length,admission_generation,admission_metadata_sha256,admission_receipt_id,provider_receipt_id):
    required=("schema","status","provider_class","provider_identity","provider_locator","provider_revision","operation_id","envelope_sha256","envelope_byte_length","project_id","branch_id","epoch_id","logical_memory_id","original_sha256","original_byte_length","admission_generation","admission_metadata_sha256","admission_receipt_id","provider_receipt_id","receipt_id","observation_id","observed_at","valid_until","currentness_status","evidence_sha256")
    _require_exact_keys(evidence,required,name="active store readback evidence")
    expected_provider_class=ACTIVE_STORE_READBACK_ROLE_BY_PURPOSE.get(expected_purpose)
    if expected_provider_class is None: raise ValueError("active store readback purpose not governed")
    if evidence["schema"]!=ACTIVE_STORE_READBACK_EVIDENCE_SCHEMA or evidence["status"]!="VERIFIED_EXACT" or evidence["provider_class"]!=expected_provider_class or evidence["currentness_status"]!="VERIFIED_CURRENT": raise ValueError("active store readback evidence status/schema invalid")
    for key in ("provider_identity","provider_locator","provider_revision","operation_id","project_id","branch_id","epoch_id","logical_memory_id","admission_generation","admission_receipt_id","provider_receipt_id","receipt_id","observation_id"): _require_str(evidence[key],key)
    validate_identity_segment(evidence["project_id"],"project_id"); validate_identity_segment(evidence["branch_id"],"branch_id"); validate_identity_segment(evidence["logical_memory_id"],"logical_memory_id")
    validate_sha256_hex(evidence["envelope_sha256"],"envelope_sha256"); _require_int(evidence["envelope_byte_length"],"envelope_byte_length")
    validate_sha256_hex(evidence["original_sha256"],"original_sha256"); _require_int(evidence["original_byte_length"],"original_byte_length"); validate_sha256_hex(evidence["admission_metadata_sha256"],"admission_metadata_sha256")
    if evidence["epoch_id"]!="R9B0": raise ValueError("active store readback epoch mismatch")
    checks={"operation_id":operation_id,"envelope_sha256":envelope_sha256,"envelope_byte_length":envelope_byte_length,"project_id":project_id,"branch_id":branch_id,"epoch_id":epoch_id,"logical_memory_id":logical_memory_id,"original_sha256":original_sha256,"original_byte_length":original_byte_length,"admission_generation":admission_generation,"admission_metadata_sha256":admission_metadata_sha256,"admission_receipt_id":admission_receipt_id,"provider_receipt_id":provider_receipt_id}
    for key,expected in checks.items():
        if evidence[key]!=expected: raise ValueError(f"active store readback evidence {key} mismatch")
    digest=_validate_document_digest(evidence,"evidence_sha256")
    _validate_current_observation(evidence["observed_at"],valid_until=evidence["valid_until"])
    validate_authority_attestation(attestation,expected_evidence_sha256=digest,expected_purpose=expected_purpose)
    return evidence

def validate_dual_active_readback_evidence(supabase_evidence,supabase_attestation,drive_evidence,drive_attestation,*,operation_id,envelope_sha256,envelope_byte_length,project_id,branch_id,epoch_id,logical_memory_id,original_sha256,original_byte_length,admission_generation,admission_metadata_sha256,admission_receipt_id,supabase_receipt_id,drive_receipt_id):
    common=dict(operation_id=operation_id,envelope_sha256=envelope_sha256,envelope_byte_length=envelope_byte_length,project_id=project_id,branch_id=branch_id,epoch_id=epoch_id,logical_memory_id=logical_memory_id,original_sha256=original_sha256,original_byte_length=original_byte_length,admission_generation=admission_generation,admission_metadata_sha256=admission_metadata_sha256,admission_receipt_id=admission_receipt_id)
    validate_active_store_readback_evidence(supabase_evidence,supabase_attestation,expected_purpose="ACTIVE_STORE_READBACK_SUPABASE",provider_receipt_id=supabase_receipt_id,**common)
    validate_active_store_readback_evidence(drive_evidence,drive_attestation,expected_purpose="ACTIVE_STORE_READBACK_DRIVE",provider_receipt_id=drive_receipt_id,**common)
    if supabase_evidence["provider_identity"]==drive_evidence["provider_identity"]: raise ValueError("dual readback provider identities must be distinct")
    if supabase_evidence["provider_locator"]==drive_evidence["provider_locator"]: raise ValueError("dual readback provider locators must be distinct")
    for key in ("operation_id","envelope_sha256","envelope_byte_length","project_id","branch_id","epoch_id","logical_memory_id","original_sha256","original_byte_length","admission_generation","admission_metadata_sha256","admission_receipt_id"):
        if supabase_evidence[key]!=drive_evidence[key]: raise ValueError(f"dual readback replica {key} mismatch")
    return {"supabase":supabase_evidence,"drive":drive_evidence}

def validate_candidate(candidate):
    _require_exact_keys(candidate,("operation_id","sha256","byte_length","provider_locator","provider_revision","parent_id","relative_path"),optional=("readback","readback_attestation"),name="inventory candidate")
    for key in ("operation_id","provider_locator","provider_revision"): _require_str(candidate[key],key)
    validate_sha256_hex(candidate["sha256"],"sha256"); _require_int(candidate["byte_length"],"byte_length"); validate_identity_segment(candidate["parent_id"],"parent_id"); validate_archive_member_path(candidate["relative_path"])
    if "readback" in candidate:
        if "readback_attestation" not in candidate: raise ValueError("candidate readback requires verifier-rooted attestation")
        validate_readback_evidence(candidate["readback"],operation_id=candidate["operation_id"],sha256=candidate["sha256"],byte_length=candidate["byte_length"],provider_locator=candidate["provider_locator"],provider_revision=candidate["provider_revision"],parent_id=candidate["parent_id"],relative_path=candidate["relative_path"])
        validate_authority_attestation(candidate["readback_attestation"],expected_evidence_sha256=candidate["readback"]["evidence_sha256"],expected_purpose="ACTIVE_PROVIDER_READBACK")
    elif "readback_attestation" in candidate:
        raise ValueError("candidate attestation without readback")
    return candidate

def validate_inventory_snapshot(document,*,expected_parent_id,expected_relative_path,expected_operation_id,authority_attestation=None,expected_evidence_sha256=None):
    required=("schema","provider_class","parent_id","relative_path","operation_id","path_scope_complete","operation_scope_complete","locator_scope_complete","receipt_id","observation_id","snapshot_revision","observed_at","valid_until","currentness_status","verifier_route","candidates","snapshot_sha256")
    _require_exact_keys(document,required,name="inventory snapshot")
    if document["schema"]!=INVENTORY_SNAPSHOT_SCHEMA or document["provider_class"]!="GOOGLE_DRIVE_DURABLE" or document["currentness_status"]!="VERIFIED_CURRENT" or document["verifier_route"]!="INDEPENDENT_PROVIDER_INVENTORY": raise ValueError("inventory snapshot schema/provider/currentness invalid")
    validate_identity_segment(document["parent_id"],"parent_id"); validate_archive_member_path(document["relative_path"]); _require_str(document["operation_id"],"operation_id")
    if document["parent_id"]!=expected_parent_id or document["relative_path"]!=expected_relative_path or document["operation_id"]!=expected_operation_id: raise ValueError("inventory snapshot scope mismatch")
    if document["path_scope_complete"] is not True or document["operation_scope_complete"] is not True or document["locator_scope_complete"] is not True: raise ValueError("inventory snapshot does not prove complete path+operation+locator search scope")
    for key in ("receipt_id","observation_id","snapshot_revision"): _require_str(document[key],key)
    digest=_validate_document_digest(document,"snapshot_sha256")
    if expected_evidence_sha256 is not None and digest!=validate_sha256_hex(expected_evidence_sha256,"expected_evidence_sha256"): raise ValueError("inventory evidence digest mismatch")
    if authority_attestation is None: raise ValueError("verifier-rooted inventory attestation is required")
    validate_authority_attestation(authority_attestation,expected_evidence_sha256=digest,expected_purpose="DRIVE_INVENTORY_SNAPSHOT")
    _validate_current_observation(document["observed_at"],valid_until=document["valid_until"])
    candidates=document["candidates"]
    if not isinstance(candidates,list): raise ValueError("inventory candidates must be a list")
    return [validate_candidate(c) for c in candidates]

def _inventory_candidates(document,*,expected_parent_id=None,expected_relative_path=None,expected_operation_id=None,authority_attestation=None,expected_evidence_sha256=None):
    if expected_parent_id is not None or expected_relative_path is not None or expected_operation_id is not None:
        if expected_parent_id is None or expected_relative_path is None or expected_operation_id is None: raise ValueError("inventory scope must be complete")
        return validate_inventory_snapshot(document,expected_parent_id=expected_parent_id,expected_relative_path=expected_relative_path,expected_operation_id=expected_operation_id,authority_attestation=authority_attestation,expected_evidence_sha256=expected_evidence_sha256)
    c=document.get("candidates",[])
    if not isinstance(c,list): raise ValueError("inventory candidates must be a list")
    return [validate_candidate(x) for x in c]

def classify_candidates(candidates,operation_id,expected_sha256,expected_byte_length,*,expected_parent_id,expected_relative_path):
    validate_sha256_hex(expected_sha256,"expected_sha256"); _require_int(expected_byte_length,"expected_byte_length"); validate_identity_segment(expected_parent_id,"parent_id"); validate_archive_member_path(expected_relative_path); _require_str(operation_id,"operation_id")
    candidates=[validate_candidate(c) for c in candidates]
    # A provider locator is a unique object identity. The same locator may not bind
    # contradictory operation/path/byte/revision identities anywhere in the snapshot.
    by_locator={}
    for c in candidates:
        identity=(c["operation_id"],c["sha256"],c["byte_length"],c["provider_revision"],c["parent_id"],c["relative_path"])
        prior=by_locator.get(c["provider_locator"])
        if prior is not None and prior!=identity:
            return {"status":"CONFLICT","reason":"PROVIDER_LOCATOR_IDENTITY_MULTIBINDING","provider_locator":c["provider_locator"]}
        by_locator[c["provider_locator"]]=identity
    bound=[c for c in candidates if c["operation_id"]==operation_id]
    if len(bound)>1:return {"status":"CONFLICT","reason":"RESERVED_OPERATION_IDENTITY_MULTIPLE","operation_id":operation_id,"candidate_count":len(bound)}
    occupants=[c for c in candidates if c["parent_id"]==expected_parent_id and c["relative_path"]==expected_relative_path]
    if len(occupants)>1:return {"status":"CONFLICT","reason":"RESERVED_PATH_MULTIPLE_OCCUPANTS","operation_id":operation_id,"candidate_count":len(occupants),"parent_id":expected_parent_id,"relative_path":expected_relative_path}
    if len(occupants)==1:
        c=occupants[0]; locator=c["provider_locator"]
        if c["operation_id"]!=operation_id:return {"status":"CONFLICT","reason":"RESERVED_PATH_OCCUPIED_MISMATCH","operation_id":operation_id,"provider_locator":locator,"expected_parent_id":expected_parent_id,"expected_relative_path":expected_relative_path,"observed_operation_id":c["operation_id"],"observed_sha256":c["sha256"],"observed_byte_length":c["byte_length"]}
        if c["sha256"]!=expected_sha256 or c["byte_length"]!=expected_byte_length:return {"status":"CONFLICT","reason":"RESERVED_OPERATION_IDENTITY_DIVERGENT","operation_id":operation_id,"provider_locator":locator,"parent_id":expected_parent_id,"relative_path":expected_relative_path,"expected_sha256":expected_sha256,"observed_sha256":c["sha256"],"expected_byte_length":expected_byte_length,"observed_byte_length":c["byte_length"]}
        if "readback" not in c or "readback_attestation" not in c:return {"status":"OUTCOME_UNKNOWN","reason":"EXACT_REUSE_READBACK_NOT_VERIFIED","operation_id":operation_id,"provider_locator":locator,"provider_revision":c["provider_revision"],"parent_id":expected_parent_id,"relative_path":expected_relative_path}
        try:
            validate_readback_evidence(c["readback"],operation_id=operation_id,sha256=expected_sha256,byte_length=expected_byte_length,provider_locator=locator,provider_revision=c["provider_revision"],parent_id=expected_parent_id,relative_path=expected_relative_path)
            validate_authority_attestation(c["readback_attestation"],expected_evidence_sha256=c["readback"]["evidence_sha256"],expected_purpose="ACTIVE_PROVIDER_READBACK")
        except ValueError:return {"status":"OUTCOME_UNKNOWN","reason":"EXACT_REUSE_READBACK_NOT_VERIFIED","operation_id":operation_id,"provider_locator":locator,"provider_revision":c["provider_revision"],"parent_id":expected_parent_id,"relative_path":expected_relative_path}
        return {"status":"VERIFIED_REUSE","operation_id":operation_id,"provider_locator":locator,"provider_revision":c["provider_revision"],"readback_receipt_id":c["readback"]["receipt_id"],"readback_observation_id":c["readback"]["observation_id"],"parent_id":expected_parent_id,"relative_path":expected_relative_path,"sha256":expected_sha256,"byte_length":expected_byte_length}
    if bound:
        c=bound[0]; return {"status":"CONFLICT","reason":"RESERVED_OPERATION_LOCATOR_PATH_MISMATCH","operation_id":operation_id,"provider_locator":c["provider_locator"],"expected_parent_id":expected_parent_id,"observed_parent_id":c["parent_id"],"expected_relative_path":expected_relative_path,"observed_relative_path":c["relative_path"]}
    return {"status":"CREATE","operation_id":operation_id,"expected_sha256":expected_sha256,"expected_byte_length":expected_byte_length,"parent_id":expected_parent_id,"relative_path":expected_relative_path}

def verify_exact_bytes(expected,readback):
    es,rs=sha256_bytes(expected),sha256_bytes(readback); exact=len(expected)==len(readback) and es==rs and expected==readback
    return {"status":"VERIFIED_EXACT" if exact else "MISMATCH","expected_byte_length":len(expected),"readback_byte_length":len(readback),"expected_sha256":es,"readback_sha256":rs}

def verify_stream_exact(expected,stream,*,profile=None,possible_effect=False,byte_limit=None,limit_reason=None,resource_field="max_decoded_bytes"):
    try:
        p=_effective_profile(profile)
        if resource_field not in VERIFY_STREAM_RESOURCE_FIELDS: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_LIMIT_FIELD_NOT_ALLOWED")
        reason=_canonical_limit_reason(resource_field)
        if limit_reason is not None and limit_reason!=reason: raise ResourceBlocked("BLOCKED_RESOURCE_PROFILE","RESOURCE_LIMIT_REASON_OVERRIDE_NOT_GOVERNED")
        governed=_profile_byte_limit(p,resource_field); limit=_bounded_numeric_override(byte_limit,governed,"RESOURCE_BYTE_LIMIT_OVERRIDE_INVALID")
        if len(expected)>limit: raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT",reason,observed=len(expected),limit=limit)
        h=hashlib.sha256(); actual=_read_stream_bounded_raw(stream,byte_limit=limit,chunk_bytes=int(p["stream_chunk_bytes"]),digest=h,limit_reason=reason)
    except ResourceBlocked as exc:return _resource_block_result(exc,after_possible_effect=False)
    r=verify_exact_bytes(expected,actual); r.update({"readback_digest_streamed":h.hexdigest(),"eof_verified":True}); return r

def validate_archive_member_path(path):
    if not isinstance(path,str) or _contains_disallowed_control(path): raise ValueError("unsafe archive member path")
    p=PurePosixPath(path)
    if not path or p.is_absolute() or ".." in p.parts or "." in p.parts or "\\" in path: raise ValueError("unsafe archive member path")
    n=str(p)
    if n.startswith("/") or n!=path: raise ValueError("non-canonical archive member path")
    return n

def _tarinfo(name,size):
    validate_archive_member_path(name); i=tarfile.TarInfo(name); i.size=size; i.mtime=0; i.mode=0o644; i.uid=i.gid=0; i.uname=i.gname=""; return i

def build_archive_generation(*,logical_memory_id,original_bytes,original_sha256,generation_id,predecessor_generation,predecessor_container_sha256,subject_id,admission_receipt_id,supabase_receipt_id,drive_receipt_id,operation_id,profile=None):
    p=_effective_profile(profile); logical_memory_id=validate_identity_segment(logical_memory_id,"logical_memory_id"); validate_sha256_hex(original_sha256,"original_sha256")
    if len(original_bytes)>int(p["max_source_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","SOURCE_BYTES_EXCEEDED",observed=len(original_bytes),limit=int(p["max_source_bytes"]))
    if len(original_bytes)>int(p["max_archive_member_expanded_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_MEMBER_BYTES_EXCEEDED",observed=len(original_bytes),limit=int(p["max_archive_member_expanded_bytes"]))
    if sha256_bytes(original_bytes)!=original_sha256: raise ValueError("original bytes do not match original_sha256")
    base=f"memories/{logical_memory_id}/{original_sha256}"; opath=validate_archive_member_path(f"{base}/original.bin"); mpath=validate_archive_member_path(f"{base}/manifest.json")
    mb=_archive_manifest_bytes(logical_memory_id=logical_memory_id,original_sha256=original_sha256,original_byte_length=len(original_bytes),generation_id=generation_id,predecessor_generation=predecessor_generation,predecessor_container_sha256=predecessor_container_sha256,subject_id=subject_id,admission_receipt_id=admission_receipt_id,supabase_receipt_id=supabase_receipt_id,drive_receipt_id=drive_receipt_id,operation_id=operation_id); cumulative=0
    for sz in (len(original_bytes),len(mb)):_limit_next(cumulative,sz,int(p["max_archive_generation_expanded_bytes"]),"ARCHIVE_GENERATION_BYTES_EXCEEDED"); cumulative+=sz
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode="w",format=tarfile.USTAR_FORMAT) as tf:
        tf.addfile(_tarinfo(opath,len(original_bytes)),io.BytesIO(original_bytes)); tf.addfile(_tarinfo(mpath,len(mb)),io.BytesIO(mb))
    raw_size=raw.tell()
    if raw_size>int(p["max_decoded_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","DECODED_ARCHIVE_BYTES_EXCEEDED",observed=raw_size,limit=int(p["max_decoded_bytes"]))
    out=io.BytesIO(); raw.seek(0)
    with gzip.GzipFile(filename="",mode="wb",fileobj=out,mtime=0,compresslevel=9) as gz:
        while True:
            chunk=raw.read(int(p["stream_chunk_bytes"]))
            if not chunk: break
            gz.write(chunk)
    archive=out.getvalue()
    if len(archive)>int(p["max_archive_generation_expanded_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_CONTAINER_BYTES_EXCEEDED",observed=len(archive),limit=int(p["max_archive_generation_expanded_bytes"]))
    _ratio_limit(raw_size,max(1,len(archive)),float(p["max_expansion_ratio"])); return archive

def verify_archive_generation(archive_bytes,*,logical_memory_id,original_sha256,expected_original,generation_id,predecessor_generation,predecessor_container_sha256,subject_id,admission_receipt_id,supabase_receipt_id,drive_receipt_id,operation_id,expected_container_sha256,expected_container_byte_length,profile=None,possible_effect=False):
    try:
        p=_effective_profile(profile); logical_memory_id=validate_identity_segment(logical_memory_id,"logical_memory_id"); validate_sha256_hex(original_sha256,"original_sha256")
        if sha256_bytes(expected_original)!=original_sha256:return {"status":"MISMATCH","reason":"ORIGINAL_EXPECTATION_SHA_MISMATCH","expected_original_sha256":sha256_bytes(expected_original),"declared_original_sha256":original_sha256}
        if not isinstance(expected_container_byte_length,int) or isinstance(expected_container_byte_length,bool) or expected_container_byte_length<0:return {"status":"MISMATCH","reason":"ARCHIVE_CONTAINER_EXPECTATION_INVALID"}
        try: validate_sha256_hex(expected_container_sha256,"expected_container_sha256")
        except ValueError:return {"status":"MISMATCH","reason":"ARCHIVE_CONTAINER_EXPECTATION_INVALID"}
        if len(expected_original)>int(p["max_source_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","SOURCE_BYTES_EXCEEDED",observed=len(expected_original),limit=int(p["max_source_bytes"]))
        if len(expected_original)>int(p["max_archive_member_expanded_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_MEMBER_BYTES_EXCEEDED",observed=len(expected_original),limit=int(p["max_archive_member_expanded_bytes"]))
        if len(archive_bytes)>int(p["max_archive_generation_expanded_bytes"]): raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_CONTAINER_BYTES_EXCEEDED",observed=len(archive_bytes),limit=int(p["max_archive_generation_expanded_bytes"]))
        observed_container_sha=sha256_bytes(archive_bytes)
        if len(archive_bytes)!=expected_container_byte_length or observed_container_sha!=expected_container_sha256:return {"status":"MISMATCH","reason":"ARCHIVE_CONTAINER_EXACTNESS_MISMATCH","expected_archive_byte_length":expected_container_byte_length,"archive_byte_length":len(archive_bytes),"expected_archive_container_sha256":expected_container_sha256,"archive_container_sha256":observed_container_sha}
        expected_manifest=_archive_manifest_bytes(logical_memory_id=logical_memory_id,original_sha256=original_sha256,original_byte_length=len(expected_original),generation_id=generation_id,predecessor_generation=predecessor_generation,predecessor_container_sha256=predecessor_container_sha256,subject_id=subject_id,admission_receipt_id=admission_receipt_id,supabase_receipt_id=supabase_receipt_id,drive_receipt_id=drive_receipt_id,operation_id=operation_id)
        gz=gzip.GzipFile(fileobj=io.BytesIO(archive_bytes),mode="rb"); decoded=io.BytesIO(); total=0
        while True:
            chunk=gz.read(int(p["stream_chunk_bytes"]))
            if not chunk: break
            _limit_next(total,len(chunk),int(p["max_decoded_bytes"]),"DECODED_ARCHIVE_BYTES_EXCEEDED"); total+=len(chunk); _ratio_limit(total,max(1,len(archive_bytes)),float(p["max_expansion_ratio"])); decoded.write(chunk)
        gz.close(); base=f"memories/{logical_memory_id}/{original_sha256}"; opath=validate_archive_member_path(f"{base}/original.bin"); mpath=validate_archive_member_path(f"{base}/manifest.json"); decoded.seek(0)
        with tarfile.open(fileobj=decoded,mode="r:") as tf:
            members=tf.getmembers(); names=[x.name for x in members]; [validate_archive_member_path(n) for n in names]
            if sorted(names)!=sorted([opath,mpath]): return {"status":"MISMATCH","reason":"ARCHIVE_MEMBER_SET_MISMATCH","members":names}
            cumulative=0
            for member in members:
                if not member.isfile():return {"status":"MISMATCH","reason":"ARCHIVE_MEMBER_TYPE_MISMATCH","member":member.name}
                if member.size>int(p["max_archive_member_expanded_bytes"]):raise ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_MEMBER_BYTES_EXCEEDED",observed=member.size,limit=int(p["max_archive_member_expanded_bytes"]))
                _limit_next(cumulative,member.size,int(p["max_archive_generation_expanded_bytes"]),"ARCHIVE_GENERATION_BYTES_EXCEEDED"); cumulative+=member.size
            om,mm=tf.extractfile(opath),tf.extractfile(mpath)
            if om is None or mm is None:return {"status":"MISMATCH","reason":"ARCHIVE_MEMBER_UNREADABLE"}
            extracted=_read_stream_profile_field(om,p,"max_archive_member_expanded_bytes"); manifest_bytes=_read_stream_profile_field(mm,p,"max_archive_member_expanded_bytes")
    except ResourceBlocked as exc:return _resource_block_result(exc,after_possible_effect=False)
    except (gzip.BadGzipFile,EOFError,tarfile.TarError,OSError,UnicodeDecodeError,json.JSONDecodeError,ValueError) as exc:return {"status":"MISMATCH","reason":"ARCHIVE_PARSE_FAILURE","detail":type(exc).__name__}
    exact=verify_exact_bytes(expected_original,extracted)
    if exact["status"]!="VERIFIED_EXACT":return {"status":"MISMATCH","reason":"ORIGINAL_READBACK_MISMATCH",**exact}
    if manifest_bytes!=expected_manifest:return {"status":"MISMATCH","reason":"ARCHIVE_MANIFEST_PROVENANCE_MISMATCH","expected_manifest_sha256":sha256_bytes(expected_manifest),"observed_manifest_sha256":sha256_bytes(manifest_bytes),"expected_manifest_byte_length":len(expected_manifest),"observed_manifest_byte_length":len(manifest_bytes)}
    return {"status":"VERIFIED_EXACT","archive_container_sha256":observed_container_sha,"archive_byte_length":len(archive_bytes),"archive_manifest_sha256":sha256_bytes(manifest_bytes),"original_sha256":original_sha256,"original_byte_length":len(expected_original),"archive_member_path":opath,"eof_verified":True}


def verify_active_readback(expected,stream,evidence,attestation=None,*,expected_evidence_sha256=None,profile=None):
    try:
        parsed=parse_memory_epoch_envelope(expected); sha=sha256_bytes(expected); parent_id=R9B0_DRIVE_PARENT_ID; relative_path=_active_relative_path(parsed["project_id"],parsed["branch_id"],parsed["logical_memory_id"],sha)
        validate_readback_evidence(evidence,operation_id=parsed["operation_id"],sha256=sha,byte_length=len(expected),parent_id=parent_id,relative_path=relative_path,expected_evidence_sha256=expected_evidence_sha256)
        if attestation is None: raise ValueError("verifier-rooted readback attestation is required")
        validate_authority_attestation(attestation,expected_evidence_sha256=evidence["evidence_sha256"],expected_purpose="ACTIVE_PROVIDER_READBACK")
    except ValueError as exc:return {"status":"MISMATCH","reason":"READBACK_EVIDENCE_INVALID","detail":str(exc)}
    r=verify_stream_exact(expected,stream,profile=profile,resource_field="max_envelope_bytes")
    if r.get("status")=="VERIFIED_EXACT":r.update({"operation_id":parsed["operation_id"],"provider_locator":evidence["provider_locator"],"provider_revision":evidence["provider_revision"],"readback_receipt_id":evidence["receipt_id"],"readback_observation_id":evidence["observation_id"],"currentness_status":evidence["currentness_status"]})
    return r

def validate_archive_readback_evidence(evidence,*,logical_memory_id,original_sha256,original_byte_length,generation_id,subject_id,admission_receipt_id,supabase_receipt_id,drive_receipt_id,operation_id,archive_container_sha256,archive_container_byte_length,expected_evidence_sha256=None):
    required=("schema","status","provider_class","archive_bundle_locator","archive_entry_locator","provider_revision","operation_id","generation_id","subject_id","archive_container_sha256","archive_container_byte_length","original_sha256","original_byte_length","archive_receipt_id","admission_receipt_id","supabase_receipt_id","drive_receipt_id","observation_id","observed_at","currentness_status","verifier_route","evidence_sha256")
    _require_exact_keys(evidence,required,name="archive readback evidence")
    if evidence["schema"]!=ARCHIVE_READBACK_EVIDENCE_SCHEMA or evidence["status"]!="VERIFIED_EXACT" or evidence["provider_class"]!="GOOGLE_DRIVE_DURABLE" or evidence["currentness_status"]!="VERIFIED_CURRENT": raise ValueError("archive evidence status/schema invalid")
    for key in ("archive_bundle_locator","archive_entry_locator","provider_revision","operation_id","generation_id","subject_id","archive_receipt_id","admission_receipt_id","supabase_receipt_id","drive_receipt_id","observation_id","verifier_route"): _require_str(evidence[key],key)
    validate_archive_member_path(evidence["archive_entry_locator"]); validate_sha256_hex(evidence["archive_container_sha256"],"archive_container_sha256"); validate_sha256_hex(evidence["original_sha256"],"original_sha256"); _require_int(evidence["archive_container_byte_length"],"archive_container_byte_length"); _require_int(evidence["original_byte_length"],"original_byte_length")
    _validate_document_digest(evidence,"evidence_sha256")
    if expected_evidence_sha256 is not None and evidence["evidence_sha256"]!=validate_sha256_hex(expected_evidence_sha256,"expected_evidence_sha256"): raise ValueError("archive evidence digest does not match trusted receipt graph")
    _validate_current_observation(evidence["observed_at"])
    expected_entry=f"memories/{validate_identity_segment(logical_memory_id,'logical_memory_id')}/{validate_sha256_hex(original_sha256,'original_sha256')}/original.bin"
    checks={"archive_entry_locator":expected_entry,"operation_id":operation_id,"generation_id":generation_id,"subject_id":subject_id,"archive_container_sha256":archive_container_sha256,"archive_container_byte_length":archive_container_byte_length,"original_sha256":original_sha256,"original_byte_length":original_byte_length,"admission_receipt_id":admission_receipt_id,"supabase_receipt_id":supabase_receipt_id,"drive_receipt_id":drive_receipt_id}
    for key,expected in checks.items():
        if evidence[key]!=expected: raise ValueError(f"archive readback evidence {key} mismatch")
    return evidence

def verify_archive_readback_with_evidence(archive_bytes,expected_original,evidence,attestation=None,*,logical_memory_id,original_sha256,generation_id,predecessor_generation,predecessor_container_sha256,subject_id,admission_receipt_id,supabase_receipt_id,drive_receipt_id,operation_id,expected_container_sha256,expected_container_byte_length,expected_evidence_sha256=None,profile=None):
    try:
        validate_archive_readback_evidence(evidence,logical_memory_id=logical_memory_id,original_sha256=original_sha256,original_byte_length=len(expected_original),generation_id=generation_id,subject_id=subject_id,admission_receipt_id=admission_receipt_id,supabase_receipt_id=supabase_receipt_id,drive_receipt_id=drive_receipt_id,operation_id=operation_id,archive_container_sha256=expected_container_sha256,archive_container_byte_length=expected_container_byte_length,expected_evidence_sha256=expected_evidence_sha256)
        if attestation is None: raise ValueError("verifier-rooted archive readback attestation is required")
        validate_authority_attestation(attestation,expected_evidence_sha256=evidence["evidence_sha256"],expected_purpose="ARCHIVE_PROVIDER_READBACK")
    except ValueError as exc:return {"status":"MISMATCH","reason":"ARCHIVE_READBACK_EVIDENCE_INVALID","detail":str(exc)}
    r=verify_archive_generation(archive_bytes,logical_memory_id=logical_memory_id,original_sha256=original_sha256,expected_original=expected_original,generation_id=generation_id,predecessor_generation=predecessor_generation,predecessor_container_sha256=predecessor_container_sha256,subject_id=subject_id,admission_receipt_id=admission_receipt_id,supabase_receipt_id=supabase_receipt_id,drive_receipt_id=drive_receipt_id,operation_id=operation_id,expected_container_sha256=expected_container_sha256,expected_container_byte_length=expected_container_byte_length,profile=profile)
    if r.get("status")=="VERIFIED_EXACT":r.update({"archive_bundle_locator":evidence["archive_bundle_locator"],"archive_entry_locator":evidence["archive_entry_locator"],"provider_revision":evidence["provider_revision"],"archive_receipt_id":evidence["archive_receipt_id"],"readback_observation_id":evidence["observation_id"],"currentness_status":evidence["currentness_status"]})
    return r

def _open_parent_dir_nofollow(path,*,create):
    path=Path(path)
    if ".." in path.parts: raise ValueError("local archive path traversal is forbidden")
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
    if path.is_absolute():
        fd=os.open("/",flags); parts=path.parts[1:]
    else:
        fd=os.open(".",flags); parts=path.parts
    try:
        for part in parts:
            if part in ("", "."): continue
            try: next_fd=os.open(part,flags,dir_fd=fd)
            except FileNotFoundError:
                if not create: raise
                os.mkdir(part,0o700,dir_fd=fd); next_fd=os.open(part,flags,dir_fd=fd)
            os.close(fd); fd=next_fd
        return fd
    except Exception:
        os.close(fd); raise

def _read_fd_bounded(fd,limit,chunk):
    out=io.BytesIO(); total=0
    while True:
        part=os.read(fd,chunk)
        if not part: break
        _limit_next(total,len(part),limit,"ARCHIVE_CONTAINER_BYTES_EXCEEDED"); total+=len(part); out.write(part)
    return out.getvalue()

def _same_file_identity(a,b):
    return stat.S_ISREG(a.st_mode) and stat.S_ISREG(b.st_mode) and a.st_dev==b.st_dev and a.st_ino==b.st_ino and a.st_nlink==1 and b.st_nlink==1

def _same_directory_identity(a,b):
    return stat.S_ISDIR(a.st_mode) and stat.S_ISDIR(b.st_mode) and a.st_dev==b.st_dev and a.st_ino==b.st_ino

def _verify_fd_current_path(parent_fd,leaf,fd,expected_bytes,*,limit,chunk):
    first=os.fstat(fd)
    if not stat.S_ISREG(first.st_mode):return False,"LOCAL_ARCHIVE_OUTPUT_UNSAFE",None
    if first.st_nlink==0:return False,"LOCAL_ARCHIVE_PATH_REPLACED",None
    if first.st_nlink!=1:return False,"LOCAL_ARCHIVE_OUTPUT_UNSAFE",None
    try: path_first=os.stat(leaf,dir_fd=parent_fd,follow_symlinks=False)
    except OSError:return False,"LOCAL_ARCHIVE_PATH_REPLACED",None
    if not _same_file_identity(first,path_first):return False,"LOCAL_ARCHIVE_PATH_REPLACED",None
    os.lseek(fd,0,os.SEEK_SET); actual=_read_fd_bounded(fd,limit,chunk)
    after=os.fstat(fd)
    try: path_after=os.stat(leaf,dir_fd=parent_fd,follow_symlinks=False)
    except OSError:return False,"LOCAL_ARCHIVE_PATH_REPLACED",actual
    if not _same_file_identity(after,path_after) or first.st_dev!=after.st_dev or first.st_ino!=after.st_ino:return False,"LOCAL_ARCHIVE_PATH_REPLACED",actual
    if after.st_size!=len(actual) or path_after.st_size!=len(actual):return False,"LOCAL_ARCHIVE_PATH_CHANGED_DURING_VERIFY",actual
    return True,None,actual

def _verify_parent_dir_current_path(parent_path,parent_fd):
    """Re-open the caller-visible parent path with the same no-follow walk and
    prove it still names the directory pinned by parent_fd."""
    current_fd=None
    try:
        current_fd=_open_parent_dir_nofollow(Path(parent_path),create=False)
        pinned=os.fstat(parent_fd); current=os.fstat(current_fd)
        return _same_directory_identity(pinned,current)
    except OSError:
        return False
    finally:
        if current_fd is not None:
            try: os.close(current_fd)
            except OSError: pass

def _final_local_archive_rebind(path,parent_fd,leaf,fd,expected_bytes,*,limit,chunk):
    ok,reason,actual=_verify_fd_current_path(parent_fd,leaf,fd,expected_bytes,limit=limit,chunk=chunk)
    if not ok:return False,reason,actual
    if actual!=expected_bytes:return False,"LOCAL_ARCHIVE_PATH_DIVERGENT",actual
    if not _verify_parent_dir_current_path(path.parent,parent_fd):
        return False,"LOCAL_ARCHIVE_PARENT_PATH_REPLACED",actual
    # Final caller-visible full-path observation resolves parent+leaf together.
    # This occurs after the pinned-directory check and is the last filesystem
    # observation before success, preventing a renamed parent from being masked
    # by a subsequent dirfd-relative leaf check against the old directory.
    pinned=os.fstat(fd)
    try: current=os.stat(path,follow_symlinks=False)
    except OSError:return False,"LOCAL_ARCHIVE_PATH_REPLACED",actual
    if not _same_file_identity(pinned,current) or pinned.st_nlink!=1:
        return False,"LOCAL_ARCHIVE_PATH_REPLACED",actual
    return True,None,actual

def create_or_verify_local_archive(path,archive_bytes,*,profile=None):
    p=_effective_profile(profile); path=Path(path); parent_fd=None; leaf=path.name; possible_effect=False
    cap=int(p["max_archive_generation_expanded_bytes"]); chunk=int(p["stream_chunk_bytes"])
    if len(archive_bytes)>cap:
        return ResourceBlocked("BLOCKED_RESOURCE_LIMIT","ARCHIVE_CONTAINER_BYTES_EXCEEDED",observed=len(archive_bytes),limit=cap).as_result()
    if not leaf or leaf in {".",".."}: return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_PATH_INVALID"}
    try:
        parent_fd=_open_parent_dir_nofollow(path.parent,create=True)
        try: st=os.stat(leaf,dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError: st=None
        if st is not None:
            if not stat.S_ISREG(st.st_mode):return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_OUTPUT_NOT_REGULAR"}
            if st.st_nlink!=1:return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_OUTPUT_HARDLINK_ALIAS","link_count":st.st_nlink}
            try: fd=os.open(leaf,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=parent_fd)
            except OSError:return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_OUTPUT_UNSAFE"}
            try:
                ok,reason,existing=_final_local_archive_rebind(path,parent_fd,leaf,fd,archive_bytes,limit=cap,chunk=chunk)
                if not ok:return {"status":"CONFLICT","reason":reason}
                return {"status":"VERIFIED_REUSE","provider_effect_performed":False,"archive_container_sha256":sha256_bytes(archive_bytes),"archive_byte_length":len(archive_bytes)}
            finally: os.close(fd)
        flags=os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
        try:
            fd=os.open(leaf,flags,0o600,dir_fd=parent_fd); possible_effect=True
        except FileExistsError:return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_CREATE_RACE"}
        except OSError as exc:
            if exc.errno in {errno.ELOOP,errno.EEXIST}:return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_CREATE_RACE"}
            raise
        try:
            fst=os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink!=1:return {"status":"MIGRATION_INCOMPLETE","reason":"LOCAL_ARCHIVE_OUTPUT_UNSAFE","provider_effect_performed":True}
            view=memoryview(archive_bytes); offset=0
            while offset<len(view): offset+=os.write(fd,view[offset:])
            os.fsync(fd)
            ok,reason,readback=_final_local_archive_rebind(path,parent_fd,leaf,fd,archive_bytes,limit=cap,chunk=chunk)
            if not ok:return {"status":"MIGRATION_INCOMPLETE","reason":reason,"provider_effect_performed":True}
            return {"status":"CREATE","provider_effect_performed":False,"archive_container_sha256":sha256_bytes(archive_bytes),"archive_byte_length":len(archive_bytes)}
        finally: os.close(fd)
    except ResourceBlocked as exc:
        return _resource_block_result(exc,after_possible_effect=possible_effect)
    except (OSError,ValueError) as exc:
        if possible_effect:return {"status":"MIGRATION_INCOMPLETE","reason":"LOCAL_ARCHIVE_POSTEFFECT_FAILURE","detail":type(exc).__name__,"provider_effect_performed":True}
        return {"status":"CONFLICT","reason":"LOCAL_ARCHIVE_PARENT_UNSAFE","detail":type(exc).__name__}
    finally:
        if parent_fd is not None:
            try: os.close(parent_fd)
            except OSError: pass

def _load_json(path):
    if path is None: raise ValueError("JSON evidence path is required")
    p=resolve_current_resource_profile(); raw=_read_path_profile_field(Path(path),p,"max_source_bytes"); v=strict_json_loads(raw)
    if not isinstance(v,dict):raise ValueError("JSON document must be an object")
    return v

def _print(result):
    print(json.dumps(result,indent=2,sort_keys=True)); return 0 if result.get("status") not in {"CONFLICT","MISMATCH","OUTCOME_UNKNOWN","PRESENT_UNVERIFIED","BLOCKED_EVIDENCE","BLOCKED_RESOURCE_PROFILE","BLOCKED_RESOURCE_LIMIT","MIGRATION_INCOMPLETE"} else 2

def _active_plan(args):
    p=resolve_current_resource_profile(); envelope=_read_path_profile_field(Path(args.envelope),p,"max_envelope_bytes")
    try: parsed=parse_memory_epoch_envelope(envelope)
    except ValueError as exc:return {"status":"CONFLICT","reason":"ENVELOPE_INVALID_OR_NONCANONICAL","detail":str(exc),"provider_effect_performed":False}
    sha=sha256_bytes(envelope); parent_id=getattr(args,"parent_id",R9B0_DRIVE_PARENT_ID)
    if parent_id!=R9B0_DRIVE_PARENT_ID:return {"status":"CONFLICT","reason":"DRIVE_PARENT_NOT_GOVERNED","expected_parent_id":R9B0_DRIVE_PARENT_ID,"observed_parent_id":parent_id,"provider_effect_performed":False}
    for name in ("project_id","branch_id","logical_memory_id"): validate_identity_segment(getattr(args,name),name)
    for name in ("project_id","branch_id","logical_memory_id"):
        if getattr(args,name)!=parsed[name]:return {"status":"CONFLICT","reason":"ENVELOPE_NAMESPACE_MISMATCH","field":name,"expected":parsed[name],"observed":getattr(args,name),"provider_effect_performed":False}
    expected_op=parsed["operation_id"]
    if getattr(args,"operation_id",None) is not None and args.operation_id!=expected_op:return {"status":"CONFLICT","reason":"OPERATION_ID_MISMATCH","operation_id":args.operation_id,"expected_operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id}
    migration_key=getattr(args,"migration_key",None)
    if migration_key is not None and migration_key!=expected_op:return {"status":"CONFLICT","reason":"MIGRATION_KEY_NOT_AUTHORITATIVE","migration_key":migration_key,"expected_operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id}
    relative_path=_active_relative_path(parsed["project_id"],parsed["branch_id"],parsed["logical_memory_id"],sha)
    if getattr(args,"inventory",None) is None or getattr(args,"inventory_attestation",None) is None:return {"status":"OUTCOME_UNKNOWN","reason":"INVENTORY_VERIFIER_ATTESTATION_REQUIRED","operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}
    try:
        document=_load_json(args.inventory); inventory_attestation=_load_json(args.inventory_attestation)
        candidates=validate_inventory_snapshot(document,expected_parent_id=parent_id,expected_relative_path=relative_path,expected_operation_id=expected_op,authority_attestation=inventory_attestation,expected_evidence_sha256=getattr(args,"inventory_evidence_sha256",None))
    except (OSError,UnicodeDecodeError,ValueError,ResourceBlocked) as exc:return {"status":"OUTCOME_UNKNOWN","reason":"INVENTORY_EVIDENCE_INVALID_OR_STALE","detail":type(exc).__name__,"operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}
    r=classify_candidates(candidates,expected_op,sha,len(envelope),expected_parent_id=parent_id,expected_relative_path=relative_path)
    if r.get("status")=="CREATE":
        governance=parsed["document"]["governance"]
        if governance["privacy_scope"]=="PRIVATE_FORBIDDEN_TO_DUPLICATE" or governance["lifecycle"]=="TOMBSTONED":
            return {"status":"BLOCKED_EVIDENCE","reason":"ACTIVE_DUPLICATION_NOT_ELIGIBLE","operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}
        if getattr(args,"admission_evidence",None) is None or getattr(args,"admission_attestation",None) is None:
            return {"status":"OUTCOME_UNKNOWN","reason":"ACTIVE_DUPLICATION_ADMISSION_EVIDENCE_REQUIRED","operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}
        try:
            admission_evidence=_load_json(args.admission_evidence); admission_attestation=_load_json(args.admission_attestation)
            validate_duplication_admission_evidence(admission_evidence,admission_attestation,parsed_envelope=parsed,envelope_sha256=sha)
        except (OSError,UnicodeDecodeError,ValueError,ResourceBlocked) as exc:
            return {"status":"OUTCOME_UNKNOWN","reason":"ACTIVE_DUPLICATION_ADMISSION_INVALID","detail":type(exc).__name__,"operation_id":expected_op,"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}
        r["admission_receipt_id"]=admission_evidence["receipt_id"]; r["admission_observation_id"]=admission_evidence["observation_id"]
    r.update({"provider_effect_performed":False,"parent_id":parent_id,"relative_path":relative_path}); return r

def build_parser():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="command",required=True)
    i=s.add_parser("inspect"); i.add_argument("--inventory",required=True); i.add_argument("--inventory-attestation",required=True); i.add_argument("--inventory-evidence-sha256"); i.add_argument("--operation-id",required=True); i.add_argument("--expected-sha256",required=True); i.add_argument("--expected-byte-length",type=int,required=True); i.add_argument("--expected-parent-id",required=True); i.add_argument("--expected-relative-path",required=True)
    a=s.add_parser("create-or-verify-active"); a.add_argument("--envelope",required=True); a.add_argument("--inventory",required=True); a.add_argument("--inventory-attestation",required=True); a.add_argument("--inventory-evidence-sha256"); a.add_argument("--admission-evidence"); a.add_argument("--admission-attestation"); a.add_argument("--operation-id"); a.add_argument("--migration-key"); a.add_argument("--project-id",required=True); a.add_argument("--branch-id",required=True); a.add_argument("--logical-memory-id",required=True); a.add_argument("--parent-id",default=R9B0_DRIVE_PARENT_ID)
    ar=s.add_parser("create-or-verify-archive-generation")
    for x in ("envelope","original","output","logical-memory-id","original-sha256","generation-id","predecessor-generation","predecessor-container-sha256","subject-id","admission-receipt-id","supabase-receipt-id","drive-receipt-id","operation-id","supabase-readback-evidence","supabase-readback-attestation","drive-readback-evidence","drive-readback-attestation"): ar.add_argument("--"+x,required=True)
    vr=s.add_parser("verify-active-readback"); vr.add_argument("--expected",required=True); vr.add_argument("--readback",required=True); vr.add_argument("--evidence",required=True); vr.add_argument("--attestation",required=True); vr.add_argument("--evidence-sha256")
    va=s.add_parser("verify-archive-readback"); va.add_argument("--archive",required=True); va.add_argument("--original",required=True); va.add_argument("--evidence",required=True); va.add_argument("--attestation",required=True); va.add_argument("--evidence-sha256"); va.add_argument("--logical-memory-id",required=True); va.add_argument("--original-sha256",required=True); va.add_argument("--expected-container-sha256",required=True); va.add_argument("--expected-container-byte-length",type=int,required=True)
    for x in ("generation-id","predecessor-generation","predecessor-container-sha256","subject-id","admission-receipt-id","supabase-receipt-id","drive-receipt-id","operation-id"): va.add_argument("--"+x,required=True)
    return p

def main(argv=None):
    args=build_parser().parse_args(argv)
    if not verifier_trust_root_configured():
        return _print({"status":"OUTCOME_UNKNOWN","reason":"VERIFIER_TRUST_ROOT_UNCONFIGURED","provider_effect_performed":False})
    try:
        if args.command=="inspect":
            doc=_load_json(args.inventory); att=_load_json(args.inventory_attestation); candidates=validate_inventory_snapshot(doc,expected_parent_id=args.expected_parent_id,expected_relative_path=args.expected_relative_path,expected_operation_id=args.operation_id,authority_attestation=att,expected_evidence_sha256=args.inventory_evidence_sha256); return _print(classify_candidates(candidates,args.operation_id,args.expected_sha256,args.expected_byte_length,expected_parent_id=args.expected_parent_id,expected_relative_path=args.expected_relative_path))
        if args.command=="create-or-verify-active":return _print(_active_plan(args))
        if args.command=="verify-active-readback":
            p=resolve_current_resource_profile(); expected=_read_path_profile_field(Path(args.expected),p,"max_envelope_bytes"); evidence=_load_json(args.evidence); attestation=_load_json(args.attestation)
            with Path(args.readback).open("rb") as fh:return _print(verify_active_readback(expected,fh,evidence,attestation,expected_evidence_sha256=args.evidence_sha256,profile=p))
        if args.command=="create-or-verify-archive-generation":
            p=resolve_current_resource_profile(); envelope=_read_path_profile_field(Path(args.envelope),p,"max_envelope_bytes"); parsed=parse_memory_epoch_envelope(envelope); original=_read_path_profile_field(Path(args.original),p,"max_source_bytes")
            document=parsed["document"]; migration=document["migration"]; original_doc=document["original"]; envelope_sha=sha256_bytes(envelope)
            if parsed["operation_id"]!=args.operation_id or parsed["logical_memory_id"]!=args.logical_memory_id: raise ValueError("archive envelope operation/namespace mismatch")
            if original_doc["sha256"]!=args.original_sha256 or original_doc["byte_length"]!=len(original) or parsed["original_bytes"]!=original: raise ValueError("archive original bytes do not match canonical envelope")
            supabase_evidence=_load_json(args.supabase_readback_evidence); supabase_attestation=_load_json(args.supabase_readback_attestation); drive_evidence=_load_json(args.drive_readback_evidence); drive_attestation=_load_json(args.drive_readback_attestation)
            validate_dual_active_readback_evidence(supabase_evidence,supabase_attestation,drive_evidence,drive_attestation,operation_id=args.operation_id,envelope_sha256=envelope_sha,envelope_byte_length=len(envelope),project_id=parsed["project_id"],branch_id=parsed["branch_id"],epoch_id=document["epoch_id"],logical_memory_id=args.logical_memory_id,original_sha256=args.original_sha256,original_byte_length=len(original),admission_generation=migration["admission_generation"],admission_metadata_sha256=migration["admission_metadata_sha256"],admission_receipt_id=args.admission_receipt_id,supabase_receipt_id=args.supabase_receipt_id,drive_receipt_id=args.drive_receipt_id)
            archive=build_archive_generation(logical_memory_id=args.logical_memory_id,original_bytes=original,original_sha256=args.original_sha256,generation_id=args.generation_id,predecessor_generation=args.predecessor_generation,predecessor_container_sha256=args.predecessor_container_sha256,subject_id=args.subject_id,admission_receipt_id=args.admission_receipt_id,supabase_receipt_id=args.supabase_receipt_id,drive_receipt_id=args.drive_receipt_id,operation_id=args.operation_id,profile=p)
            return _print(create_or_verify_local_archive(Path(args.output),archive,profile=p))
        if args.command=="verify-archive-readback":
            p=resolve_current_resource_profile(); archive=_read_path_profile_field(Path(args.archive),p,"max_archive_generation_expanded_bytes"); original=_read_path_profile_field(Path(args.original),p,"max_source_bytes"); evidence=_load_json(args.evidence); attestation=_load_json(args.attestation); return _print(verify_archive_readback_with_evidence(archive,original,evidence,attestation,logical_memory_id=args.logical_memory_id,original_sha256=args.original_sha256,generation_id=args.generation_id,predecessor_generation=args.predecessor_generation,predecessor_container_sha256=args.predecessor_container_sha256,subject_id=args.subject_id,admission_receipt_id=args.admission_receipt_id,supabase_receipt_id=args.supabase_receipt_id,drive_receipt_id=args.drive_receipt_id,operation_id=args.operation_id,expected_container_sha256=args.expected_container_sha256,expected_container_byte_length=args.expected_container_byte_length,expected_evidence_sha256=args.evidence_sha256,profile=p))
    except ResourceBlocked as exc:return _print(exc.as_result())
    except (OSError,UnicodeDecodeError,ValueError) as exc:return _print({"status":"OUTCOME_UNKNOWN","reason":"INVALID_OR_UNREADABLE_EVIDENCE","detail":type(exc).__name__})
    raise AssertionError("unreachable command")

if __name__=="__main__":raise SystemExit(main())
