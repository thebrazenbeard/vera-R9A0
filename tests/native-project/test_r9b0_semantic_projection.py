from __future__ import annotations

import copy
import hashlib
import json
import math
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROJECTION_PATH = ROOT / "validation" / "R9B0_SEMANTIC_PROJECTION_MANIFEST.json"
PROFILE_PATH = ROOT / "validation" / "VERA_BEHAVIOR_PROFILE_V1.json"
EPOCH_PATH = ROOT / "validation" / "R9B0_MEMORY_EPOCH_CONTRACT.json"
OBLIGATION_PATH = ROOT / "validation" / "R9B0_NATIVE_OBLIGATION_MATRIX.json"
EPOCH_SCHEMA_PATH = ROOT / "schemas" / "native-project" / "r9b0_memory_epoch_envelope_v1.schema.json"


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def native_clause_map(text: str) -> dict[str, str]:
    clauses: dict[str, str] = {}
    for line in text.splitlines(keepends=True):
        if line.startswith("K") and len(line) >= 4 and line[1:3].isdigit() and line[3] == " ":
            cid = line[:3]
            if cid in clauses:
                raise AssertionError(f"duplicate native clause {cid}")
            clauses[cid] = line
    return clauses


def validate_native_obligations(text: str, matrix: dict) -> list[str]:
    errors: list[str] = []
    clauses = native_clause_map(text)
    expected_ids = [o["id"] for o in matrix["obligations"]]
    if list(clauses) != expected_ids:
        errors.append(f"ids/order mismatch: {list(clauses)} != {expected_ids}")
    for obligation in matrix["obligations"]:
        cid = obligation["id"]
        line = clauses.get(cid)
        if line is None:
            errors.append(f"missing {cid}")
            continue
        b = line.encode("utf-8")
        if len(b) != obligation["native_clause_utf8_bytes_including_lf"]:
            errors.append(f"{cid} byte count")
        if sha256(b) != obligation["native_clause_sha256"]:
            errors.append(f"{cid} sha256")
    return errors



def validate_resource_profile(profile: dict | None, resource: dict, *, current: bool = True, internally_consistent: bool = True) -> list[str]:
    errors: list[str] = []
    if profile is None:
        return ["BLOCKED_RESOURCE_PROFILE:missing"]
    if not current:
        errors.append("BLOCKED_RESOURCE_PROFILE:stale")
    required = resource["profile"]["required_fields"]
    for field in required:
        if field not in profile:
            errors.append(f"BLOCKED_RESOURCE_PROFILE:missing:{field}")
            continue
        value = profile[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            errors.append(f"BLOCKED_RESOURCE_PROFILE:invalid:{field}")
    if not internally_consistent:
        errors.append("BLOCKED_RESOURCE_PROFILE:inconsistent")
    return errors


def resource_guard_result(*, limit: int, observed: int, effect_may_exist: bool = False) -> str:
    if observed <= limit:
        return "WITHIN_RESOURCE_BOUND"
    return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"


def ratio_guard_result(*, expanded: int, encoded_consumed: int, max_ratio: float, effect_may_exist: bool = False) -> str:
    if encoded_consumed <= 0:
        return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"
    if expanded / encoded_consumed <= max_ratio:
        return "WITHIN_RESOURCE_BOUND"
    return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"


def validate_resource_contract(resource: dict) -> list[str]:
    errors: list[str] = []
    expected_fields = [
        "max_source_bytes", "max_decoded_bytes", "max_envelope_bytes",
        "max_archive_member_expanded_bytes", "max_archive_generation_expanded_bytes",
        "max_expansion_ratio", "stream_chunk_bytes",
    ]
    if resource.get("profile", {}).get("binding") != "MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT":
        errors.append("profile binding")
    if resource.get("profile", {}).get("required_fields") != expected_fields:
        errors.append("profile fields")
    if set(resource.get("measurement_points", {})) != {"SOURCE", "DECODE", "ENVELOPE", "ARCHIVE_MEMBER", "ARCHIVE_GENERATION"}:
        errors.append("measurement points")
    streaming = resource.get("streaming", {})
    if streaming.get("required") is not True or streaming.get("unbounded_eager_decode_or_decompression") != "PROHIBITED":
        errors.append("bounded streaming")
    success = set(streaming.get("success_requires", []))
    if not {"EOF_OR_END_OF_MEMBER", "EXACT_FULL_BYTE_DIGEST_VERIFICATION", "REQUIRED_READBACK"} <= success:
        errors.append("EOF/digest/readback")
    outcomes = set(resource.get("typed_outcomes", {}))
    if not {"BLOCKED_RESOURCE_PROFILE", "BLOCKED_RESOURCE_LIMIT", "MIGRATION_INCOMPLETE", "MIGRATED_VERIFIED"} <= outcomes:
        errors.append("typed outcomes")
    fidelity = resource.get("full_fidelity", {})
    if fidelity.get("required") is not True or "never the represented memory" not in fidelity.get("rule", ""):
        errors.append("full fidelity")
    forbidden = set(fidelity.get("forbidden_fallbacks", []))
    if not {"truncation", "summary", "projection substitute", "partial decode", "prefix-only acceptance", "skipped EOF", "skipped digest", "resource-driven semantic reduction"} <= forbidden:
        errors.append("forbidden fallback")
    if len(resource.get("required_negative_tests", [])) != 11:
        errors.append("negative count")
    if len(resource.get("required_mutation_failures", [])) != 8:
        errors.append("mutation count")
    recovery = resource.get("partial_effect_recovery", {})
    if "inspect all possibly affected providers" not in recovery.get("rule", "") or "missing/noncommitted side" not in recovery.get("retry", ""):
        errors.append("partial effect recovery")
    return errors

def validate_provenance_retrieval_contract(provenance: dict, schema: dict) -> list[str]:
    """Evaluate the exact closed provenance/retrieval-time constraints used by MemoryEpochEnvelopeV1."""
    errors: list[str] = []
    ps = schema["properties"]["provenance"]
    allowed = set(ps["properties"])
    required = set(ps["required"])
    missing = sorted(required - set(provenance))
    if missing:
        errors.append(f"missing:{','.join(missing)}")
    extra = sorted(set(provenance) - allowed)
    if ps.get("additionalProperties") is False and extra:
        errors.append(f"extra:{','.join(extra)}")
    if "retrieval_time" in provenance:
        rt = provenance["retrieval_time"]
        if rt is not None and not isinstance(rt, str):
            errors.append("retrieval_time:type")
        if rt is None and "RETRIEVAL_TIME_UNKNOWN" not in provenance.get("limitations", []):
            errors.append("retrieval_time:null_without_limitation")
    return errors


class R9B0SemanticProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(PROJECTION_PATH.read_text(encoding="utf-8"))
        cls.profile_bytes = PROFILE_PATH.read_bytes()
        cls.profile = json.loads(cls.profile_bytes.decode("utf-8"))
        cls.epoch = json.loads(EPOCH_PATH.read_text(encoding="utf-8"))
        cls.obligations = json.loads(OBLIGATION_PATH.read_text(encoding="utf-8"))
        cls.epoch_schema = json.loads(EPOCH_SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.surfaces = {
           ²È="24€€€€€€€€€€€‰É•½É‘}Ñ¥µ”ˆè€ˆÈÀÈØ´ÀÄ´ÀÉPÀÀèÀÀèÀÁhˆ°(€€€€€€€€€€€€‰ÍÑ…Ñ•}Ñ¥µ”ˆè€ˆÈÀÈØ´ÀÄ´ÀÍPÀÀèÀÀèÀÁhˆ°(€€€€€€€€€€€€‰É•ÑÉ¥•Ù…±}Ñ¥µ”ˆè€ˆÈÀÈØ´ÀÄ´ÀÑPÀÀèÀÀèÀÁhˆ°(€€€€€€€€€€€€‰±¥µ¥Ñ…Ñ¥½¹Ìˆèmt°(€€€€€€€ô(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Ù…±¥‘…Ñ•}ÁÉ½Ù•¹…¹•}É•ÑÉ¥•Ù…±}½¹ÑÉ…Ð¡ÁÉ½Ø°Í•±˜¹•Á½¡}Í¡•µ„¤°mt¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡±•¸¡íÁÉ½Ùl‰•Ù•¹Ñ}Ñ¥µ”‰t°ÁÉ½Ùl‰É•½É‘}Ñ¥µ”‰t°ÁÉ½Ùl‰ÍÑ…Ñ•}Ñ¥µ”‰t°ÁÉ½Ùl‰É•ÑÉ¥•Ù…±}Ñ¥µ”‰uô¤°€Ð¤(€€€€€€€µÕÑ…Ñ•€ô‘¥Ð¡ÁÉ½Ø°É•ÑÉ¥•Ù…±}Ñ¥µ”õ9½¹”°±¥µ¥Ñ…Ñ¥½¹Ìõl‰IQI%Y1}Q%5}U9-9=]8‰t€¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Ù…±¥‘…Ñ•}ÁÉ½Ù•¹…¹•}É•ÑÉ¥•Ù…±}½¹ÑÉ…Ð¡µÕÑ…Ñ•°Í•±˜¹•Á½¡}Í¡•µ„¤°mt¤(€€€€€€€ÝÉ½¹}ÑåÁ”€ô‘¥Ð¡ÁÉ½Ø°É•ÑÉ¥•Ù…±}Ñ¥µ”ôÄÈÌ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰É•ÑÉ¥•Ù…±}Ñ¥µ”éÑåÁ”ˆ°Ù…±¥‘…Ñ•}ÁÉ½Ù•¹…¹•}É•ÑÉ¥•Ù…±}½¹ÑÉ…Ð¡ÝÉ½¹}ÑåÁ”°Í•±˜¹•Á½¡}Í¡•µ„¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰É•ÑÉ¥•Ù…±}Ñ¥µ”ˆ°Í•±˜¹•Á½¡l‰•¹Ù•±½Á”‰ul‰É•ÑÉ¥•Ù…±}Ñ¥µ•}ÉÕ±”‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰‘¥ÍÑ¥¹Ð™É½´•Ù•¹Ñ}Ñ¥µ”ˆ°Í•±˜¹•Á½¡l‰•¹Ù•±½Á”‰ul‰É•ÑÉ¥•Ù…±}Ñ¥µ•}ÉÕ±”‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰IQI%Y1}Q%5}U9-9=]8ˆ°Í•±˜¹µ…¹¥™•ÍÑl‰Í•µ…¹Ñ¥}™…µ¥±¥•Ì‰ul‰µ•µ½Éå}•Á½ ‰ul‰É•ÑÉ¥•Ù…±}Ñ¥µ•}ÉÕ±”‰t¤(((€€€‘•˜Ñ•ÍÑ|ÈÙ}É•Í½ÕÉ•}ÁÉ•ÁÉ½‘Õ•É}¥¹ÁÕÑ}¥Í}•á…Ñ}µÕ¹•}Ù•É¥™¥•‘}ØÉ}¹½Ñ}ØÄ¡Í•±˜¤è(€€€€€€€È€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰ul‰Í½ÕÉ•}¥¹ÁÕÐ‰t(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Él‰…ÉÑ¥™…Ð‰t°€‰	PÉ}HåÁ}%!Q}I!%Y}IM=UI}=9QIQ|ÌÐá}XÈˆ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Él‰Í±…­}µ•ÍÍ…•}ÑÌ‰t°€ˆÄÜàÜÌÄÔÄÐä¸ÈÌÄØÜäˆ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Él‰ÕÑ˜á}‰åÑ•Ì‰t°€ÌäÄÔ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Él‰Í¡„ÈÔØ‰t°€ˆå˜Ñ˜Ý…ÌÈÅÄÉ•™ˆÜÝ‰„á„ÐÑ•‰•ŒÍ”ØÌäÄäÝ‰•”ÔÍŒÍ„ÔÌÄÉÅØÌÌå™™ŒÝ…ˆ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰AMM} Á}4Àˆ°Él‰Ù•É‘¥Ð‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰U9I=YI	1}U9YI%%ˆ°Él‰ØÅ}ÍÑ…ÑÕÌ‰t¤(€€€€€€€´€ôÍ•±˜¹µ…¹¥™•ÍÑl‰É•Í½ÕÉ•}ÁÉ•ÁÉ½‘Õ•É}¥¹ÁÕÐ‰t(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡µl‰Í¡„ÈÔØ‰t°Él‰Í¡„ÈÔØ‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡µl‰ÕÑ˜á}‰åÑ•Ì‰t°€ÌäÄÔ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡µl‰ØÅ}ÍÑ…ÑÕÌ‰t°€‰U9I=YI	1}U9YI%%ˆ¤((€€€‘•˜Ñ•ÍÑ|ÈÝ}É•Í½ÕÉ•}ÁÉ½™¥±•}¥Í}Ù•ÉÍ¥½¹•‘}½µÁ±•Ñ•}Á½Í¥Ñ¥Ù•}™¥¹¥Ñ•}…¹‘}™…¥±}±½Í•¡Í•±˜¤è(€€€€€€€É•Í½ÕÉ”€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€ÁÉ½™¥±”€ôì(€€€€€€€€€€€€‰µ…á}Í½ÕÉ•}‰åÑ•Ìˆè€ÄÀÀÀ°(€€€€€€€€€€€€‰µ…á}‘•½‘•‘}‰åÑ•Ìˆè€ÈÀÀÀ°(€€€€€€€€€€€€‰µ…á}•¹Ù•±½Á•}‰åÑ•Ìˆè€ÌÀÀÀ°(€€€€€€€€€€€€‰µ…á}…É¡¥Ù•}µ•µ‰•É}•áÁ…¹‘•‘}‰åÑ•Ìˆè€ÐÀÀÀ°(€€€€€€€€€€€€‰µ…á}…É¡¥Ù•}•¹•É…Ñ¥½¹}•áÁ…¹‘•‘}‰åÑ•Ìˆè€àÀÀÀ°(€€€€€€€€€€€€‰µ…á}•áÁ…¹Í¥½¹}É…Ñ¥¼ˆè€ÈÀ¸À°(€€€€€€€€€€€€‰ÍÑÉ•…µ}¡Õ¹­}‰åÑ•Ìˆè€ÈÔØ°(€€€€€€€ô(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡ÁÉ½™¥±”°É•Í½ÕÉ”¤°mt¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰µ¥ÍÍ¥¹œˆ°Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡9½¹”°É•Í½ÕÉ”¥lÁt¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰ÍÑ…±”ˆ°€ˆ€ˆ¹©½¥¸¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡ÁÉ½™¥±”°É•Í½ÕÉ”°ÕÉÉ•¹Ðõ…±Í”¤¤¤(€€€€€€€¹½¹™¥¹¥Ñ”€ô‘¥Ð¡ÁÉ½™¥±”°µ…á}•áÁ…¹Í¥½¹}É…Ñ¥¼õ™±½…Ð ‰¥¹˜ˆ¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰¥¹Ù…±¥éµ…á}•áÁ…¹Í¥½¹}É…Ñ¥¼ˆ°€ˆ€ˆ¹©½¥¸¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡¹½¹™¥¹¥Ñ”°É•Í½ÕÉ”¤¤¤(€€€€€€€¹½¹Á½Í¥Ñ¥Ù”€ô‘¥Ð¡ÁÉ½™¥±”°µ…á}Í½ÕÉ•}‰åÑ•ÌôÀ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰¥¹Ù…±¥éµ…á}Í½ÕÉ•}‰åÑ•Ìˆ°€ˆ€ˆ¹©½¥¸¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡¹½¹Á½Í¥Ñ¥Ù”°É•Í½ÕÉ”¤¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰¥¹½¹Í¥ÍÑ•¹Ðˆ°€ˆ€ˆ¹©½¥¸¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}ÁÉ½™¥±”¡ÁÉ½™¥±”°É•Í½ÕÉ”°¥¹Ñ•É¹…±±å}½¹Í¥ÍÑ•¹Ðõ…±Í”¤¤¤((€€€‘•˜Ñ•ÍÑ|Èá}É•Í½ÕÉ•}Í½ÕÉ•}‘•½‘•}•¹Ù•±½Á•}…Á}Á±ÕÍ}½¹•}™…¥±}‰•™½É•}•™™•Ð¡Í•±˜¤è(€€€€€€€É•Í½ÕÉ”€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€Á½¥¹ÑÌ€ôÉ•Í½ÕÉ•l‰µ•…ÍÕÉ•µ•¹Ñ}Á½¥¹ÑÌ‰t(€€€€€€€™½ÈÁ½¥¹Ð¥¸€ ‰M=UIˆ°€‰=ˆ°€‰9Y1=Aˆ¤è(€€€€€€€€€€€Ý¥Ñ Í•±˜¹ÍÕ‰Q•ÍÐ¡Á½¥¹ÐõÁ½¥¹Ð¤è(€€€€€€€€€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰‰•™½É”ˆ°Á½¥¹ÑÍmÁ½¥¹Ñt¹±½Ý•È ¤¤(€€€€€€€™½È±¥µ¥Ð¥¸€ ÄÀÀ°€ÄÀÀÀ°€ÐÀäØ¤è(€€€€€€€€€€€Ý¥Ñ Í•±˜¹ÍÕ‰Q•ÍÐ¡±¥µ¥Ðõ±¥µ¥Ð¤è(€€€€€€€€€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É•Í½ÕÉ•}Õ…É‘}É•ÍÕ±Ð¡±¥µ¥Ðõ±¥µ¥Ð°½‰Í•ÉÙ•õ±¥µ¥Ð¤°€‰]%Q!%9}IM=UI}	=U9ˆ¤(€€€€€€€€€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É•Í½ÕÉ•}Õ…É‘}É•ÍÕ±Ð¡±¥µ¥Ðõ±¥µ¥Ð°½‰Í•ÉÙ•õ±¥µ¥Ð€¬€Ä¤°€‰	1=-}IM=UI}1%5%Pˆ¤((€€€‘•˜Ñ•ÍÑ|Èå}É•Í½ÕÉ•}…É¡¥Ù•}É…Ñ¥½}µ•µ‰•É}…¹‘}•¹•É…Ñ¥½¹}¡½ÍÑ¥±•Í}™…¥±}±½Í•¡Í•±˜¤è(€€€€€€€È€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰É…Ñ¥¼ˆ°Él‰µ•…ÍÕÉ•µ•¹Ñ}Á½¥¹ÑÌ‰ul‰I!%Y}55	H‰t¹±½Ý•È ¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰…É½ÍÌ…±°µ•µ‰•ÉÌˆ°Él‰µ•…ÍÕÉ•µ•¹Ñ}Á½¥¹ÑÌ‰ul‰I!%Y}9IQ%=8‰t¹±½Ý•È ¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É…Ñ¥½}Õ…É‘}É•ÍÕ±Ð¡•áÁ…¹‘•ôäää°•¹½‘•‘}½¹ÍÕµ•ôÄÀÀ°µ…á}É…Ñ¥¼ôÄÀ¸À¤°€‰]%Q!%9}IM=UI}	=U9ˆ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É…Ñ¥½}Õ…É‘}É•ÍÕ±Ð¡•áÁ…¹‘•ôÄÀÀÄ°•¹½‘•‘}½¹ÍÕµ•ôÄÀÀ°µ…á}É…Ñ¥¼ôÄÀ¸À¤°€‰	1=-}IM=UI}1%5%Pˆ¤(€€€€€€€µ•µ‰•É}±¥µ¥Ð€ô€ÄÀÀÀ(€€€€€€€•¹•É…Ñ¥½¹}±¥µ¥Ð€ô€ÄÔÀÀ(€€€€€€€µ•µ‰•ÉÌ€ôläÀÀ°€äÀÁt(€€€€€€€Í•±˜¹…ÍÍ•ÉÑQÉÕ”¡…±°¡à€ðôµ•µ‰•É}±¥µ¥Ð™½Èà¥¸µ•µ‰•ÉÌ¤¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É•Í½ÕÉ•}Õ…É‘}É•ÍÕ±Ð¡±¥µ¥Ðõ•¹•É…Ñ¥½¹}±¥µ¥Ð°½‰Í•ÉÙ•õÍÕ´¡µ•µ‰•ÉÌ¤¤°€‰	1=-}IM=UI}1%5%Pˆ¤((€€€‘•˜Ñ•ÍÑ|ÌÁ}É•Í½ÕÉ•}•½™}‘¥•ÍÑ}…¹‘}ÑÉÕ¹…Ñ•‘}ÁÉ•™¥á}…¹}¹•Ù•É}Á…ÍÌ¡Í•±˜¤è(€€€€€€€È€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€É•Ä€ôÍ•Ð¡Él‰ÍÑÉ•…µ¥¹œ‰ul‰ÍÕ•ÍÍ}É•ÅÕ¥É•Ì‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰=}=I}9}=}55	Hˆ°É•Ä¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰aQ}U11}	eQ}%MQ}YI%%Q%=8ˆ°É•Ä¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰IEU%I}I	,ˆ°É•Ä¤(€€€€€€€¹•…Ñ¥Ù•Ì€ôÍ•Ð¡Él‰É•ÅÕ¥É•‘}¹•…Ñ¥Ù•}Ñ•ÍÑÌ‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰ÑÉÕ¹…Ñ•µ•µ‰•ÈÝ¥Ñ µ…Ñ¡¥¹œ‘¥•ÍÐÁÉ•™¥àˆ°¹•…Ñ¥Ù•Ì¤(€€€€€€€™½É‰¥‘‘•¸€ôÍ•Ð¡Él‰™Õ±±}™¥‘•±¥Ñä‰ul‰™½É‰¥‘‘•¹}™…±±‰…­Ì‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰ÁÉ•™¥àµ½¹±ä…•ÁÑ…¹”ˆ°™½É‰¥‘‘•¸¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰Í­¥ÁÁ•=ˆ°™½É‰¥‘‘•¸¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰Í­¥ÁÁ•‘¥•ÍÐˆ°™½É‰¥‘‘•¸¤((€€€‘•˜Ñ•ÍÑ|ÌÅ}É•Í½ÕÉ•}Á½ÍÑ}•™™•Ñ}‰É•…¡}¥Í}¥¹½µÁ±•Ñ•}…¹‘}ÁÉ•Í•ÉÙ•Í}ÍÕ•ÍÍ™Õ±}Í¥‘”¡Í•±˜¤è(€€€€€€€È€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡É•Í½ÕÉ•}Õ…É‘}É•ÍÕ±Ð¡±¥µ¥ÐôÄÀÀ°½‰Í•ÉÙ•ôÄÀÄ°•™™•Ñ}µ…å}•á¥ÍÐõQÉÕ”¤°€‰5%IQ%=9}%9=5A1Qˆ¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰•á¥ÍÑÌ½Èµ…ä•á¥ÍÐˆ°Él‰ÑåÁ•‘}½ÕÑ½µ•Ì‰ul‰5%IQ%=9}%9=5A1Q‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰¥¹ÍÁ•Ð•™™•ÑÌ‰•™½É”É•ÑÉäˆ°Él‰ÑåÁ•‘}½ÕÑ½µ•Ì‰ul‰5%IQ%=9}%9=5A1Q‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰µ¥ÍÍ¥¹œ½¹½¹½µµ¥ÑÑ•Í¥‘”ˆ°Él‰Á…ÉÑ¥…±}•™™•Ñ}É•½Ù•Éä‰ul‰É•ÑÉä‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑ%¸ ‰•É…Í”„ÍÕ•ÍÍ™Õ°Í¥‘”ˆ°Él‰Á…ÉÑ¥…±}•™™•Ñ}É•½Ù•Éä‰ul‰ÁÉ½¡¥‰¥Ð‰t¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Í•±˜¹µ…¹¥™•ÍÑl‰Í•µ…¹Ñ¥}™…µ¥±¥•Ì‰ul‰µ•µ½Éå}•Á½ ‰ul‰É•Í½ÕÉ•}Á½ÍÑ}Á½ÍÍ¥‰±•}•™™•Ñ}™…¥±ÕÉ”‰t°€‰5%IQ%=9}%9=5A1Qˆ¤((€€€‘•˜Ñ•ÍÑ|ÌÉ}É•Í½ÕÉ•}½¹ÑÉ…Ñ}µÕÑ…Ñ¥½¹}½É}Í•µ…¹Ñ¥}Ý•…­•¹¥¹}™…¥±Ì¡Í•±˜¤è(€€€€€€€È€ôÍ•±˜¹•Á½¡l‰É•Í½ÕÉ•}Í…™•Ñä‰t(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}½¹ÑÉ…Ð¡È¤°mt¤(€€€€€€€µÕÑ…Ñ¥½¹Ì€ômt(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰™Õ±±}™¥‘•±¥Ñä‰ul‰™½É‰¥‘‘•¹}™…±±‰…­Ì‰t¹É•µ½Ù” ‰ÑÉÕ¹…Ñ¥½¸ˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰™Õ±±}™¥‘•±¥Ñä‰ul‰™½É‰¥‘‘•¹}™…±±‰…­Ì‰t¹É•µ½Ù” ‰ÍÕµµ…Éäˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰ÍÑÉ•…µ¥¹œ‰ul‰ÍÕ•ÍÍ}É•ÅÕ¥É•Ì‰t¹É•µ½Ù” ‰=}=I}9}=}55	Hˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰ÍÑÉ•…µ¥¹œ‰ul‰ÍÕ•ÍÍ}É•ÅÕ¥É•Ì‰t¹É•µ½Ù” ‰aQ}U11}	eQ}%MQ}YI%%Q%=8ˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰µ•…ÍÕÉ•µ•¹Ñ}Á½¥¹ÑÌ‰ul‰I!%Y}55	H‰t€ô€‰ÕµÕ±…Ñ¥Ù”•áÁ…¹‘•‰åÑ•Ì½¹±äˆìál‰µ•…ÍÕÉ•µ•¹Ñ}Á½¥¹ÑÌ‰t¹Á½À ‰I!%Y}9IQ%=8ˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰ÍÑÉ•…µ¥¹œ‰ul‰Õ¹‰½Õ¹‘•‘}•…•É}‘•½‘•}½É}‘•½µÁÉ•ÍÍ¥½¸‰t€ô€‰11=]ˆìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰ÑåÁ•‘}½ÕÑ½µ•Ì‰t¹Á½À ‰5%IQ%=9}%9=5A1Qˆ¤ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€à€ô½Áä¹‘••Á½Áä¡È¤ìál‰™Õ±±}™¥‘•±¥Ñä‰ul‰É•ÅÕ¥É•‰t€ô…±Í”ìµÕÑ…Ñ¥½¹Ì¹…ÁÁ•¹¡à¤(€€€€€€€Í•±˜¹…ÍÍ•ÉÑÅÕ…°¡±•¸¡µÕÑ…Ñ¥½¹Ì¤°±•¸¡Él‰É•ÅÕ¥É•‘}µÕÑ…Ñ¥½¹}™…¥±ÕÉ•Ì‰t¤¤(€€€€€€€™½È¤°µÕÑ…Ñ•¥¸•¹Õµ•É…Ñ”¡µÕÑ…Ñ¥½¹Ì°€Ä¤è(€€€€€€€€€€€Ý¥Ñ Í•±˜¹ÍÕ‰Q•ÍÐ¡µÕÑ…Ñ¥½¸õ¤¤è(€€€€€€€€€€€€€€€Í•±˜¹…ÍÍ•ÉÑQÉÕ”¡Ù…±¥‘…Ñ•}É•Í½ÕÉ•}½¹ÑÉ…Ð¡µÕÑ…Ñ•¤¤(()¥˜}}¹…µ•}|€ôô€‰}}µ…¥¹}|ˆè(€€€Õ¹¥ÑÑ•ÍÐ¹µ…¥¸ ¤(