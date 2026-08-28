from __future__ import annotations
import base64, datetime as dt, gzip, hashlib, importlib.util, inspect, io, json, os, pathlib, tarfile, tempfile, types, unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[2]
HELPER=ROOT/'scripts'/'r9b0_memory_epoch_drive.py'
EXPECTED_COMMANDS={'inspect','create-or-verify-active','verify-active-readback','create-or-verify-archive-generation','verify-archive-readback'}

TEST_EVIDENCE_AUTHORITY_ID='BT2_R9B0_TEST_VERIFIER_ONLY'
TEST_EVIDENCE_KEY_ID='BT2_R9B0_TEST_RSA_ONLY'

def load_helper():
    spec=importlib.util.spec_from_file_location('r9b0_memory_epoch_drive',HELPER); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    mod.EVIDENCE_TRUST_ROOT_STATE='CONFIGURED'
    mod.EVIDENCE_AUTHORITY_ID=TEST_EVIDENCE_AUTHORITY_ID
    mod.EVIDENCE_KEY_ID=TEST_EVIDENCE_KEY_ID
    mod._EVIDENCE_RSA_N=TEST_RSA_N
    return mod


def _digest_doc(doc, field):
    body=dict(doc); body.pop(field,None)
    return hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()


# TEST-ONLY NON-AUTHORITY KEYPAIR. Its public key is injected only into the
# imported test module; production ships with no configured verifier key.
TEST_RSA_N=int("bb160e11ae9c50127b00ed651a033cb4a78600359d1ddc1a2507df50f7bc6af7e5bc42d22db2372f20daf44a57af0de4711f85f58e658a207bf6d37196bf4f7de7616749ee12400fb73ab4ca52bbde3f3ad29eae50293a8f65d691dc9ee4738dfda06355a8004c0fb82a83cdb9648f7657bc26492af1e899efc20b17202432ab0fe61ccde4a7afa2094411b550236f1cbfb9fe96e741bf1bf998c8849296dd6fd6bf9355f6b4bdbd288e60d09c820e352e540991b3deb6f9178523c57f8585c1ff107c256c551dc62ce3748a787250ff22a06ad6fc3da22f773db3eae430e2686d0b9329d635e6fffbed0cc1c0e4227e42913c06fe87df66b607d7f50d655239",16)
TEST_RSA_D=int("1be3dbd11300c6871ac336a0bdd201b8c4c89b3b62e2d2af2b1a135694b8081250b3521ad7291c44f056f3d8295e3569fadb42332b3943f037cac216caec564364bd0692e4e4df9bf82ace4ce32c92a34677a3a444db0099e40aaad002f7f7aa114759c7a935f220ddc9a8c08084d746432a0f6314fddf39239effdc40b464c10dbfeb5ff39a335bd9c9cfb8c008268418ba1a6c35e38986e6eeec4282f6ec67d511a715fbcd8686bab0236b8f15ca9e224a10fece9d3ad94953e1ff34d627d51d02f99c4e87cdd0df48c3c86043bc3daedba983a0f00e9b364faf17cd5a5b341227261fc28d59d816437eadf28329fecdeb614c52fb3643d880b04712b28121",16)

def _rsa_sign_sha256(message):
    k=(TEST_RSA_N.bit_length()+7)//8
    digest=hashlib.sha256(message).digest()
    di=bytes.fromhex("3031300d060960864801650304020105000420")+digest
    em=b"\x00\x01"+b"\xff"*(k-len(di)-3)+b"\x00"+di
    return pow(int.from_bytes(em,"big"),TEST_RSA_D,TEST_RSA_N).to_bytes(k,"big")

def make_attestation(evidence_sha256,purpose):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    doc={'schema':'R9B0_VERIFIER_AUTHORITY_ATTESTATION_V1','authority_id':TEST_EVIDENCE_AUTHORITY_ID,'key_id':TEST_EVIDENCE_KEY_ID,'purpose':purpose,'evidence_sha256':evidence_sha256,'issued_at':now.isoformat().replace('+00:00','Z'),'valid_until':(now+dt.timedelta(seconds=240)).isoformat().replace('+00:00','Z'),'nonce':'test-nonce','signature_base64':''}
    body=dict(doc); body.pop('signature_base64')
    raw=json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    doc['signature_base64']=base64.b64encode(_rsa_sign_sha256(raw)).decode()
    return doc

def write_doc(root,name,doc):
    p=pathlib.Path(root)/name; p.write_text(json.dumps(doc,separators=(',',':'))); return str(p)

def make_envelope(m, *, project_id='p1', branch_id='b1', logical_memory_id='m1', source_version='v1', admission_generation='admit-v1', original=b'abc'):
    original_sha=hashlib.sha256(original).hexdigest()
    op=m.memory_epoch_operation_identity(['R9B0',project_id,branch_id,logical_memory_id,source_version,original_sha,admission_generation])
    obj={
        'schema':'MemoryEpochEnvelopeV1','version':'1.0.1','epoch_id':'R9B0',
        'project_id':project_id,'branch_id':branch_id,'logical_memory_id':logical_memory_id,'memory_class':'WORKING_PROJECT',
        'original':{'provider_class':'TEST_SOURCE','source_locator':'source://x','source_version_or_generation':source_version,'record_identity':'record-1','content_type':'application/octet-stream','byte_length':len(original),'sha256':original_sha,'bytes_base64':__import__('base64').b64encode(original).decode()},
        'provenance':{'source_actor':'tester','epistemic_class':'OBSERVED','source_evidence':['fixture'],'event_time':None,'record_time':None,'state_time':None,'retrieval_time':None,'limitations':['RETRIEVAL_TIME_UNKNOWN']},
        'governance':{'privacy_scope':'PROJECT','lifecycle':'ACTIVE','admission_authority_ref':'authority-1','contradiction_links':[],'supersession_links':[],'tombstone_links':[],'currentness_rule':'REVALIDATE_ON_USE'},
        'indexing':{'semantic_keys':[],'aliases':[],'tags':[],'relationships':[],'literal_phrases':[],'temporal_anchors':[]},
        'migration':{'operation_id':op,'attempt_id':'attempt-1','source_snapshot_digest':hashlib.sha256(b'snapshot').hexdigest(),'target_epoch':'R9B0','admission_generation':admission_generation,'admission_metadata_sha256':hashlib.sha256(b'admission').hexdigest()},
    }
    raw=json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return raw,obj,op

def make_readback_evidence(*, operation_id, sha256, byte_length, provider_locator, provider_revision, parent_id, relative_path):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    doc={'schema':'R9B0_PROVIDER_READBACK_EVIDENCE_V1','status':'VERIFIED_EXACT','provider_class':'GOOGLE_DRIVE_DURABLE','provider_locator':provider_locator,'provider_revision':provider_revision,'operation_id':operation_id,'parent_id':parent_id,'relative_path':relative_path,'sha256':sha256,'byte_length':byte_length,'receipt_id':'receipt-1','observation_id':'obs-1','observed_at':now.isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','verifier_route':'INDEPENDENT_PROVIDER_READBACK','evidence_sha256':''}
    doc['evidence_sha256']=_digest_doc(doc,'evidence_sha256'); return doc

def make_candidate(*, operation_id, sha256, byte_length, provider_locator, parent_id, relative_path, provider_revision='rev-1', with_readback=True):
    c={'operation_id':operation_id,'sha256':sha256,'byte_length':byte_length,'provider_locator':provider_locator,'provider_revision':provider_revision,'parent_id':parent_id,'relative_path':relative_path}
    if with_readback:
        c['readback']=make_readback_evidence(operation_id=operation_id,sha256=sha256,byte_length=byte_length,provider_locator=provider_locator,provider_revision=provider_revision,parent_id=parent_id,relative_path=relative_path)
        c['readback_attestation']=make_attestation(c['readback']['evidence_sha256'],'ACTIVE_PROVIDER_READBACK')
    return c

def make_inventory(candidates, *, parent_id, relative_path, operation_id, age_seconds=0, valid_for_seconds=240):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    observed=now-dt.timedelta(seconds=age_seconds); valid_until=observed+dt.timedelta(seconds=valid_for_seconds)
    doc={'schema':'R9B0_DRIVE_INVENTORY_SNAPSHOT_V1','provider_class':'GOOGLE_DRIVE_DURABLE','parent_id':parent_id,'relative_path':relative_path,'operation_id':operation_id,'path_scope_complete':True,'operation_scope_complete':True,'locator_scope_complete':True,'receipt_id':'inventory-receipt-1','observation_id':'inventory-observation-1','snapshot_revision':'query-rev-1','observed_at':observed.isoformat().replace('+00:00','Z'),'valid_until':valid_until.isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','verifier_route':'INDEPENDENT_PROVIDER_INVENTORY','candidates':candidates,'snapshot_sha256':''}
    doc['snapshot_sha256']=_digest_doc(doc,'snapshot_sha256'); return doc



def make_admission_evidence(raw,obj,op):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    doc={'schema':'R9B0_ACTIVE_DUPLICATION_ADMISSION_EVIDENCE_V1','status':'VERIFIED_ELIGIBLE','operation_id':op,'envelope_sha256':hashlib.sha256(raw).hexdigest(),'admission_authority_ref':obj['governance']['admission_authority_ref'],'admission_generation':obj['migration']['admission_generation'],'admission_metadata_sha256':obj['migration']['admission_metadata_sha256'],'privacy_scope':obj['governance']['privacy_scope'],'lifecycle':obj['governance']['lifecycle'],'duplication_eligible':True,'receipt_id':'admission-receipt-current','observation_id':'admission-obs-current','observed_at':now.isoformat().replace('+00:00','Z'),'valid_until':(now+dt.timedelta(seconds=240)).isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','evidence_sha256':''}
    doc['evidence_sha256']=_digest_doc(doc,'evidence_sha256'); return doc

def make_active_store_readback(*,provider_class,operation_id,logical_memory_id,original_sha256,original_byte_length,admission_receipt_id,provider_receipt_id,locator,envelope_sha256='0'*64,envelope_byte_length=1,project_id='p',branch_id='b',epoch_id='R9B0',admission_generation='admit-v1',admission_metadata_sha256='2'*64,provider_identity=None):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if provider_identity is None: provider_identity=provider_class+'-identity'
    doc={'schema':'R9B0_ACTIVE_STORE_READBACK_EVIDENCE_V1','status':'VERIFIED_EXACT','provider_class':provider_class,'provider_identity':provider_identity,'provider_locator':locator,'provider_revision':'rev-current','operation_id':operation_id,'envelope_sha256':envelope_sha256,'envelope_byte_length':envelope_byte_length,'project_id':project_id,'branch_id':branch_id,'epoch_id':epoch_id,'logical_memory_id':logical_memory_id,'original_sha256':original_sha256,'original_byte_length':original_byte_length,'admission_generation':admission_generation,'admission_metadata_sha256':admission_metadata_sha256,'admission_receipt_id':admission_receipt_id,'provider_receipt_id':provider_receipt_id,'receipt_id':'readback-'+provider_class,'observation_id':'obs-'+provider_class,'observed_at':now.isoformat().replace('+00:00','Z'),'valid_until':(now+dt.timedelta(seconds=240)).isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','evidence_sha256':''}
    doc['evidence_sha256']=_digest_doc(doc,'evidence_sha256'); return doc

def make_archive_evidence(*, archive_bundle_locator, archive_entry_locator, provider_revision, archive_container_sha256, archive_container_byte_length, original_sha256, original_byte_length, generation_id, subject_id, admission_receipt_id, supabase_receipt_id, drive_receipt_id, operation_id, observation_id='obs-a', verifier_route='INDEPENDENT_PROVIDER_READBACK'):
    now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    doc={'schema':'R9B0_ARCHIVE_READBACK_EVIDENCE_V1','status':'VERIFIED_EXACT','provider_class':'GOOGLE_DRIVE_DURABLE','archive_bundle_locator':archive_bundle_locator,'archive_entry_locator':archive_entry_locator,'provider_revision':provider_revision,'operation_id':operation_id,'generation_id':generation_id,'subject_id':subject_id,'archive_container_sha256':archive_container_sha256,'archive_container_byte_length':archive_container_byte_length,'original_sha256':original_sha256,'original_byte_length':original_byte_length,'archive_receipt_id':'archive-receipt-1','admission_receipt_id':admission_receipt_id,'supabase_receipt_id':supabase_receipt_id,'drive_receipt_id':drive_receipt_id,'observation_id':observation_id,'observed_at':now.isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','verifier_route':verifier_route,'evidence_sha256':''}
    doc['evidence_sha256']=_digest_doc(doc,'evidence_sha256'); return doc

class TestR9B0DualStoreImplementation(unittest.TestCase):
    def test_helper_surface_and_provider_free(self):
        m=load_helper(); self.assertEqual(set(m.COMMANDS),EXPECTED_COMMANDS); s=HELPER.read_text().lower()
        for x in ('import requests','import httpx','urllib.request','googleapiclient','google.auth','import supabase','import boto3'): self.assertNotIn(x,s)
    def test_operation_identity(self):
        m=load_helper(); a=m.operation_identity('R9B0_PROVIDER_EFFECT_V1',['alpha','b']); self.assertEqual(a,m.operation_identity('R9B0_PROVIDER_EFFECT_V1',['alpha','b'])); self.assertNotEqual(a,m.operation_identity('R9B0_PROVIDER_EFFECT_V1',['a','lphab'])); self.assertNotEqual(a,m.operation_identity('R9B0_ARCHIVE_EFFECT_V1',['alpha','b']))
    def test_candidate_conflict_semantics(self):
        m=load_helper(); payload=b'abc'; sha=hashlib.sha256(payload).hexdigest(); op='op'; parent='parent'; rel=f'active/p/b/m/{sha}.memory-epoch.json'; ck=dict(expected_parent_id=parent,expected_relative_path=rel)
        self.assertEqual(m.classify_candidates([],op,sha,3,**ck)['status'],'CREATE')
        exact=[make_candidate(operation_id=op,sha256=sha,byte_length=3,provider_locator='f',parent_id=parent,relative_path=rel)]
        self.assertEqual(m.classify_candidates(exact,op,sha,3,**ck)['status'],'VERIFIED_REUSE'); self.assertEqual(m.classify_candidates(exact+exact,op,sha,3,**ck)['status'],'CONFLICT')
    def test_exact_readback(self):
        m=load_helper(); self.assertEqual(m.verify_exact_bytes(b'x',b'x')['status'],'VERIFIED_EXACT'); self.assertEqual(m.verify_exact_bytes(b'x',b'y')['status'],'MISMATCH')
    def test_archive_roundtrip_deterministic(self):
        m=load_helper(); original=b'\x00original\xff'; sha=hashlib.sha256(original).hexdigest(); provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o'); a=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha); self.assertEqual(a,m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha)); r=m.verify_archive_generation(a,**provenance,original_sha256=sha,expected_original=original,expected_container_sha256=hashlib.sha256(a).hexdigest(),expected_container_byte_length=len(a)); self.assertEqual(r['status'],'VERIFIED_EXACT'); self.assertTrue(r['eof_verified'])
    def test_profile_missing_stale_invalid(self):
        m=load_helper();
        with self.assertRaises(m.ResourceBlocked) as c:m.validate_resource_profile(None)
        self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_PROFILE')
        current=m.resolve_current_resource_profile()
        with self.assertRaises(m.ResourceBlocked):m.validate_resource_profile(dict(current,stream_chunk_bytes=0))

    def test_current_profile_binding_is_registry_governed(self):
        m=load_helper(); profile=m.resolve_current_resource_profile()
        required={'max_source_bytes','max_decoded_bytes','max_envelope_bytes','max_archive_member_expanded_bytes','max_archive_generation_expanded_bytes','max_expansion_ratio','stream_chunk_bytes'}
        self.assertTrue(required.issubset(profile)); self.assertNotIn('current',profile)
        forged=dict(profile,current=True)
        with self.assertRaises(m.ResourceBlocked) as c:m.resolve_current_resource_profile(forged)
        self.assertEqual(c.exception.reason,'RESOURCE_PROFILE_BINDING_SCHEMA')

    def test_noncurrent_direct_profile_injection_is_blocked(self):
        m=load_helper(); governed=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_CURRENT',max_source_bytes=8,max_decoded_bytes=64,max_envelope_bytes=64,max_archive_member_expanded_bytes=64,max_archive_generation_expanded_bytes=4096,stream_chunk_bytes=4)
        registry={'TIGHT_CURRENT':governed}
        binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TIGHT_CURRENT','profile_sha256':m.resource_profile_sha256(governed)}
        forged_alt=dict(governed,profile_id='FORGED_LOOSE',max_source_bytes=100)
        forged_same_id=dict(governed,max_source_bytes=100)
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            original=b'123456789'; sha=hashlib.sha256(original).hexdigest(); kw=dict(logical_memory_id='m',original_bytes=original,original_sha256=sha,generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
            for forged in (forged_alt,forged_same_id):
                with self.subTest(profile_id=forged['profile_id']):
                    with self.assertRaises(m.ResourceBlocked) as c:m.build_archive_generation(**kw,profile=forged)
                    self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_PROFILE')
                    self.assertEqual(c.exception.reason,'RESOURCE_PROFILE_OVERRIDE_NOT_CURRENT')
                    r=m.verify_stream_exact(original,io.BytesIO(original),profile=forged,byte_limit=100)
                    self.assertEqual(r['status'],'BLOCKED_RESOURCE_PROFILE'); self.assertEqual(r['reason'],'RESOURCE_PROFILE_OVERRIDE_NOT_CURRENT')

    def test_envelope_cap_plus_one_blocks_active_plan(self):
        m=load_helper(); profile=dict(m.resolve_current_resource_profile(),profile_id='TEST_PROFILE',max_source_bytes=100,max_decoded_bytes=100,max_envelope_bytes=8,max_archive_member_expanded_bytes=100,max_archive_generation_expanded_bytes=200,stream_chunk_bytes=4)
        registry={'TEST_PROFILE':profile}
        binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TEST_PROFILE','profile_sha256':m.resource_profile_sha256(profile)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            with tempfile.TemporaryDirectory() as td:
                envelope=pathlib.Path(td)/'envelope.json'; envelope.write_bytes(b'123456789')
                args=types.SimpleNamespace(envelope=str(envelope),operation_id='op',migration_key='mk',project_id='p',branch_id='b',logical_memory_id='m',inventory=None)
                with self.assertRaises(m.ResourceBlocked) as c:m._active_plan(args)
                self.assertEqual(c.exception.reason,'ENVELOPE_BYTES_EXCEEDED'); self.assertEqual(c.exception.observed,9); self.assertEqual(c.exception.limit,8)

    def test_source_cap_plus_one(self):
        m=load_helper();
        with self.assertRaises(m.ResourceBlocked) as c:m.read_stream_bounded(io.BytesIO(b'123456789'),byte_limit=8,chunk_bytes=4)
        self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(c.exception.observed,9); self.assertEqual(c.exception.limit,8)
    def test_cumulative_generation_limit(self):
        m=load_helper(); original=b'x'*32; p=dict(m.resolve_current_resource_profile(),profile_id='TEST_GENERATION_LIMIT',max_source_bytes=1000,max_archive_member_expanded_bytes=64,max_archive_generation_expanded_bytes=64)
        registry={'TEST_GENERATION_LIMIT':p}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TEST_GENERATION_LIMIT','profile_sha256':m.resource_profile_sha256(p)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            with self.assertRaises(m.ResourceBlocked) as c:m.build_archive_generation(logical_memory_id='m',original_bytes=original,original_sha256=hashlib.sha256(original).hexdigest(),generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        self.assertEqual(c.exception.reason,'ARCHIVE_GENERATION_BYTES_EXCEEDED')
    def test_high_expansion_pre_vs_post_effect(self):
        m=load_helper(); original=b'A'*20000; sha=hashlib.sha256(original).hexdigest(); provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        loose=dict(m.resolve_current_resource_profile(),profile_id='TEST_EXPANSION_LOOSE',max_expansion_ratio=1000.0); loose_registry={'TEST_EXPANSION_LOOSE':loose}; loose_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TEST_EXPANSION_LOOSE','profile_sha256':m.resource_profile_sha256(loose)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',loose_registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',loose_binding):
            archive=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha)
        verify_kw=dict(provenance,original_sha256=sha,expected_original=original,expected_container_sha256=hashlib.sha256(archive).hexdigest(),expected_container_byte_length=len(archive))
        tight=dict(m.resolve_current_resource_profile(),profile_id='TEST_EXPANSION_TIGHT',max_expansion_ratio=1.1); tight_registry={'TEST_EXPANSION_TIGHT':tight}; tight_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TEST_EXPANSION_TIGHT','profile_sha256':m.resource_profile_sha256(tight)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',tight_registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',tight_binding):
            pre=m.verify_archive_generation(archive,**verify_kw); asserted_post=m.verify_archive_generation(archive,possible_effect=True,**verify_kw)
            synthetic=m.ResourceBlocked('BLOCKED_RESOURCE_LIMIT','EXPANSION_RATIO_EXCEEDED')
            internal_post=m._resource_block_result(synthetic,after_possible_effect=True)
        self.assertEqual(pre['status'],'BLOCKED_RESOURCE_LIMIT')
        self.assertEqual(asserted_post['status'],'BLOCKED_RESOURCE_LIMIT')
        self.assertEqual(internal_post['status'],'MIGRATION_INCOMPLETE')
    def test_truncated_archive_not_verified(self):
        m=load_helper(); original=b'archive-source'*100; sha=hashlib.sha256(original).hexdigest(); provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o'); a=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha); r=m.verify_archive_generation(a[:-7],**provenance,original_sha256=sha,expected_original=original,expected_container_sha256=hashlib.sha256(a).hexdigest(),expected_container_byte_length=len(a)); self.assertNotEqual(r['status'],'VERIFIED_EXACT')
    def test_no_eager_path_read_bytes(self):
        s=HELPER.read_text(); self.assertNotIn('.read_bytes()',s); self.assertIn('read_path_bounded',s); self.assertIn('BLOCKED_RESOURCE_LIMIT',s); self.assertIn('MIGRATION_INCOMPLETE',s)
    def test_stream_digest_and_eof(self):
        m=load_helper(); e=b'abcdef'*100; r=m.verify_stream_exact(e,io.BytesIO(e)); self.assertEqual(r['status'],'VERIFIED_EXACT'); self.assertTrue(r['eof_verified']); self.assertEqual(r['readback_digest_streamed'],hashlib.sha256(e).hexdigest())

    def test_numeric_limit_and_chunk_overrides_cannot_weaken_governed_caps(self):
        m=load_helper(); governed=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_NUMERIC',max_source_bytes=8,max_decoded_bytes=8,max_envelope_bytes=8,max_archive_member_expanded_bytes=8,max_archive_generation_expanded_bytes=64,stream_chunk_bytes=4)
        registry={'TIGHT_NUMERIC':governed}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TIGHT_NUMERIC','profile_sha256':m.resource_profile_sha256(governed)}
        class Tracking(io.BytesIO):
            def __init__(self,data): super().__init__(data); self.requests=[]
            def read(self,n=-1): self.requests.append(n); return super().read(n)
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            r=m.verify_stream_exact(b'123456789',io.BytesIO(b'123456789'),byte_limit=100)
            self.assertEqual(r['status'],'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(r['observed'],9); self.assertEqual(r['limit'],8)
            stream=Tracking(b'123456789')
            with self.assertRaises(m.ResourceBlocked) as c:m.read_stream_bounded(stream,byte_limit=100,chunk_bytes=100)
            self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(c.exception.limit,8)
            self.assertTrue(stream.requests); self.assertTrue(all(n<=4 for n in stream.requests if n>=0))
            with self.assertRaises(m.ResourceBlocked) as c:m.read_stream_bounded(io.BytesIO(b'x'),chunk_bytes=0.5)
            self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_PROFILE'); self.assertEqual(c.exception.reason,'RESOURCE_CHUNK_OVERRIDE_INVALID')

    def test_registered_noncurrent_binding_selector_is_blocked(self):
        m=load_helper(); current=m.resolve_current_resource_profile()
        tight=dict(current,profile_id='CURRENT_TIGHT',max_source_bytes=8)
        loose=dict(current,profile_id='REGISTERED_LOOSE',max_source_bytes=100)
        registry={'CURRENT_TIGHT':tight,'REGISTERED_LOOSE':loose}
        current_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'CURRENT_TIGHT','profile_sha256':m.resource_profile_sha256(tight)}
        loose_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'REGISTERED_LOOSE','profile_sha256':m.resource_profile_sha256(loose)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',current_binding):
            with self.assertRaises(m.ResourceBlocked) as c:m.resolve_current_resource_profile(loose_binding)
        self.assertEqual(c.exception.status,'BLOCKED_RESOURCE_PROFILE'); self.assertEqual(c.exception.reason,'RESOURCE_PROFILE_BINDING_OVERRIDE_NOT_CURRENT')

    def test_possible_effect_flag_cannot_self_retype_pre_effect_resource_block(self):
        m=load_helper(); governed=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_EFFECT',max_decoded_bytes=8,max_source_bytes=8,max_archive_member_expanded_bytes=8,max_archive_generation_expanded_bytes=8,stream_chunk_bytes=4)
        registry={'TIGHT_EFFECT':governed}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TIGHT_EFFECT','profile_sha256':m.resource_profile_sha256(governed)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            r=m.verify_stream_exact(b'123456789',io.BytesIO(b'123456789'),possible_effect=True)
            self.assertEqual(r['status'],'BLOCKED_RESOURCE_LIMIT')
            provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
            ar=m.verify_archive_generation(b'123456789',**provenance,original_sha256=hashlib.sha256(b'x').hexdigest(),expected_original=b'x',expected_container_sha256=hashlib.sha256(b'123456789').hexdigest(),expected_container_byte_length=9,possible_effect=True)
            self.assertEqual(ar['status'],'BLOCKED_RESOURCE_LIMIT')

    def test_expected_verification_bytes_obey_governed_limits(self):
        m=load_helper(); governed=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_EXPECTED',max_source_bytes=8,max_decoded_bytes=8,max_envelope_bytes=8,max_archive_member_expanded_bytes=8,max_archive_generation_expanded_bytes=64,stream_chunk_bytes=4)
        registry={'TIGHT_EXPECTED':governed}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TIGHT_EXPECTED','profile_sha256':m.resource_profile_sha256(governed)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            r=m.verify_stream_exact(b'123456789',io.BytesIO(b''))
            self.assertEqual(r['status'],'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(r['limit'],8)
            provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
            ar=m.verify_archive_generation(b'',**provenance,original_sha256=hashlib.sha256(b'123456789').hexdigest(),expected_original=b'123456789',expected_container_sha256=hashlib.sha256(b'').hexdigest(),expected_container_byte_length=0)
            self.assertEqual(ar['status'],'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(ar['limit'],8)

    def test_limit_reason_override_cannot_spoof_governed_reason(self):
        m=load_helper(); governed=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_REASON',max_decoded_bytes=8,stream_chunk_bytes=4)
        registry={'TIGHT_REASON':governed}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':'TIGHT_REASON','profile_sha256':m.resource_profile_sha256(governed)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            r=m.verify_stream_exact(b'123456789',io.BytesIO(b'123456789'),byte_limit=100,limit_reason='FORGED_REASON')
        self.assertEqual(r['status'],'BLOCKED_RESOURCE_PROFILE'); self.assertEqual(r['reason'],'RESOURCE_LIMIT_REASON_OVERRIDE_NOT_GOVERNED')

    def test_verify_stream_resource_field_selector_is_constrained(self):
        m=load_helper()
        r=m.verify_stream_exact(b'x',io.BytesIO(b'x'),resource_field='max_archive_generation_expanded_bytes')
        self.assertEqual(r['status'],'BLOCKED_RESOURCE_PROFILE'); self.assertEqual(r['reason'],'RESOURCE_LIMIT_FIELD_NOT_ALLOWED')


    def test_active_plan_crossbinds_envelope_namespace_operation_and_governed_parent(self):
        m=load_helper()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); raw,obj,op=make_envelope(m); envelope=root/'envelope.json'; envelope.write_bytes(raw)
            sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
            invdoc=make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op); inventory=root/'inventory.json'; inventory.write_text(json.dumps(invdoc,separators=(',',':')))
            invatt=root/'inventory.att.json'; invatt.write_text(json.dumps(make_attestation(invdoc['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT')))
            admission=make_admission_evidence(raw,obj,op); admp=root/'admission.json'; admp.write_text(json.dumps(admission)); admatt=root/'admission.att.json'; admatt.write_text(json.dumps(make_attestation(admission['evidence_sha256'],'ACTIVE_DUPLICATION_ADMISSION')))
            def args(**overrides):
                snapshot=json.loads(inventory.read_text())
                inva=make_attestation(snapshot['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT'); invatt.write_text(json.dumps(inva))
                base=dict(envelope=str(envelope),operation_id=op,migration_key=op,project_id='p1',branch_id='b1',logical_memory_id='m1',inventory=str(inventory),inventory_attestation=str(invatt),inventory_evidence_sha256=snapshot['snapshot_sha256'],admission_evidence=str(admp),admission_attestation=str(admatt),parent_id=m.R9B0_DRIVE_PARENT_ID)
                base.update(overrides); return types.SimpleNamespace(**base)
            p1=m._active_plan(args()); self.assertEqual(p1['status'],'CREATE'); self.assertEqual(p1['operation_id'],op)
            for changed in (dict(project_id='p2'),dict(branch_id='b2'),dict(logical_memory_id='m2'),dict(parent_id='ATTACKER_PARENT'),dict(migration_key='FORGED')):
                with self.subTest(changed=changed):
                    other=m._active_plan(args(**changed)); self.assertEqual(other['status'],'CONFLICT')
            bad=m._active_plan(args(operation_id='FORGED')); self.assertEqual(bad['status'],'CONFLICT')
            candidate=make_candidate(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file-p1',parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel)
            invdoc=make_inventory([candidate],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op); inventory.write_text(json.dumps(invdoc,separators=(',',':')))
            reuse=m._active_plan(args()); self.assertEqual(reuse['status'],'VERIFIED_REUSE')

    def test_archive_manifest_provenance_is_exactly_crossbound(self):
        m=load_helper(); sig=inspect.signature(m.verify_archive_generation)
        required={'generation_id','predecessor_generation','predecessor_container_sha256','subject_id','admission_receipt_id','supabase_receipt_id','drive_receipt_id','operation_id'}
        self.assertTrue(required.issubset(sig.parameters))
        original=b'provenance-source'; sha=hashlib.sha256(original).hexdigest()
        expected=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        build=dict(expected,original_bytes=original,original_sha256=sha)
        archive=m.build_archive_generation(**build)
        verify=dict(expected,original_sha256=sha,expected_original=original,expected_container_sha256=hashlib.sha256(archive).hexdigest(),expected_container_byte_length=len(archive))
        self.assertEqual(m.verify_archive_generation(archive,**verify)['status'],'VERIFIED_EXACT')
        for field in sorted(required):
            tampered_build=dict(build); tampered_build[field]=('2'*64 if field=='predecessor_container_sha256' else 'tampered-'+field)
            tampered=m.build_archive_generation(**tampered_build)
            r=m.verify_archive_generation(tampered,**dict(verify,expected_container_sha256=hashlib.sha256(tampered).hexdigest(),expected_container_byte_length=len(tampered)))
            with self.subTest(field=field):
                self.assertEqual(r['status'],'MISMATCH'); self.assertEqual(r['reason'],'ARCHIVE_MANIFEST_PROVENANCE_MISMATCH')

    def test_archive_container_exactness_rejects_semantically_equal_recompression(self):
        m=load_helper(); sig=inspect.signature(m.verify_archive_generation)
        self.assertIn('expected_container_sha256',sig.parameters); self.assertIn('expected_container_byte_length',sig.parameters)
        original=b'container-source'*20; sha=hashlib.sha256(original).hexdigest()
        provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        archive=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha)
        decoded=gzip.decompress(archive)
        out=io.BytesIO()
        with gzip.GzipFile(filename='',mode='wb',fileobj=out,mtime=123,compresslevel=9) as gz: gz.write(decoded)
        recompressed=out.getvalue(); self.assertNotEqual(hashlib.sha256(recompressed).hexdigest(),hashlib.sha256(archive).hexdigest())
        r=m.verify_archive_generation(recompressed,**provenance,original_sha256=sha,expected_original=original,expected_container_sha256=hashlib.sha256(archive).hexdigest(),expected_container_byte_length=len(archive))
        self.assertEqual(r['status'],'MISMATCH'); self.assertEqual(r['reason'],'ARCHIVE_CONTAINER_EXACTNESS_MISMATCH')

    def test_archive_verifier_enforces_cumulative_generation_member_cap_pre_next_member(self):
        m=load_helper(); original=b'A'*600; sha=hashlib.sha256(original).hexdigest(); provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        loose=dict(m.resolve_current_resource_profile(),profile_id='LOOSE_VERIFY_GEN',max_source_bytes=20000,max_decoded_bytes=20000,max_archive_member_expanded_bytes=20000,max_archive_generation_expanded_bytes=20000,max_expansion_ratio=1000.0,stream_chunk_bytes=64)
        loose_registry={loose['profile_id']:loose}; loose_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':loose['profile_id'],'profile_sha256':m.resource_profile_sha256(loose)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',loose_registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',loose_binding):
            archive=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive)),mode='r:') as tf: sizes=[x.size for x in tf.getmembers()]
        cap=max(sizes); self.assertLess(cap,sum(sizes))
        tight=dict(loose,profile_id='TIGHT_VERIFY_GEN',max_archive_member_expanded_bytes=cap,max_archive_generation_expanded_bytes=cap)
        tight_registry={tight['profile_id']:tight}; tight_binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':tight['profile_id'],'profile_sha256':m.resource_profile_sha256(tight)}
        with mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',tight_registry), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',tight_binding):
            sig=inspect.signature(m.verify_archive_generation)
            kwargs=dict(logical_memory_id='m',original_sha256=sha,expected_original=original)
            if 'generation_id' in sig.parameters: kwargs.update(provenance)
            if 'expected_container_sha256' in sig.parameters: kwargs.update(expected_container_sha256=hashlib.sha256(archive).hexdigest(),expected_container_byte_length=len(archive))
            r=m.verify_archive_generation(archive,**kwargs)
        self.assertEqual(r['status'],'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(r['reason'],'ARCHIVE_GENERATION_BYTES_EXCEEDED'); self.assertGreater(r['observed'],r['limit'])

    def test_archive_logical_memory_identity_is_single_canonical_segment(self):
        m=load_helper(); original=b'x'; sha=hashlib.sha256(original).hexdigest(); base=dict(original_bytes=original,original_sha256=sha,generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        for bad in ('m/x','../m','m\\x','.'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError): m.build_archive_generation(logical_memory_id=bad,**base)

    def test_namespace_and_archive_paths_reject_control_and_format_characters(self):
        m=load_helper()
        controls=["\n","\t","\r","\x1f","\x7f","\u200b"]
        for bad_char in controls:
            with self.subTest(kind="identity", codepoint=ord(bad_char)):
                with self.assertRaises(ValueError):
                    m.validate_identity_segment("good"+bad_char+"evil","segment")
            with self.subTest(kind="archive_path", codepoint=ord(bad_char)):
                with self.assertRaises(ValueError):
                    m.validate_archive_member_path("memories/good"+bad_char+"evil/original.bin")

    def test_expected_path_occupancy_is_reserved_independently_of_operation_id(self):
        m=load_helper(); payload=b"abc"; sha=hashlib.sha256(payload).hexdigest()
        op="expected-op"; parent="parent"; rel=f"active/p/b/m/{sha}.memory-epoch.json"
        ck=dict(expected_parent_id=parent,expected_relative_path=rel)
        exact=make_candidate(operation_id=op,sha256=sha,byte_length=3,provider_locator='file-exact',parent_id=parent,relative_path=rel)
        wrong_op_same=make_candidate(operation_id='wrong-op',sha256=sha,byte_length=3,provider_locator='file-wrong',parent_id=parent,relative_path=rel,with_readback=False)
        wrong_op_divergent=make_candidate(operation_id='wrong-op',sha256='0'*64,byte_length=3,provider_locator='file-div',parent_id=parent,relative_path=rel,with_readback=False)
        for candidate in (wrong_op_same,wrong_op_divergent):
            with self.subTest(candidate=candidate["provider_locator"]):
                r=m.classify_candidates([candidate],op,sha,3,**ck)
                self.assertEqual(r["status"],"CONFLICT")
                self.assertEqual(r["reason"],"RESERVED_PATH_OCCUPIED_MISMATCH")
        r=m.classify_candidates([exact,wrong_op_same],op,sha,3,**ck)
        self.assertEqual(r["status"],"CONFLICT")
        self.assertEqual(r["reason"],"RESERVED_PATH_MULTIPLE_OCCUPANTS")
        elsewhere=dict(wrong_op_same,relative_path="active/p/b/m/elsewhere.memory-epoch.json")
        self.assertEqual(m.classify_candidates([elsewhere],op,sha,3,**ck)["status"],"CREATE")

    def test_active_plan_requires_fresh_strict_inventory_snapshot(self):
        m=load_helper()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); raw,obj,op=make_envelope(m); env=root/'e.json'; env.write_bytes(raw)
            sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
            admission=make_admission_evidence(raw,obj,op); admp=write_doc(root,'admission.json',admission); admatt=write_doc(root,'admission.att.json',make_attestation(admission['evidence_sha256'],'ACTIVE_DUPLICATION_ADMISSION'))
            def args(inv):
                if inv is None:
                    return types.SimpleNamespace(envelope=str(env),operation_id=op,migration_key=op,project_id='p1',branch_id='b1',logical_memory_id='m1',inventory=None,inventory_attestation=None,inventory_evidence_sha256=None,admission_evidence=admp,admission_attestation=admatt,parent_id=m.R9B0_DRIVE_PARENT_ID)
                doc=json.loads(pathlib.Path(inv).read_text()); att=write_doc(root,'inventory.att.json',make_attestation(doc['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT'))
                return types.SimpleNamespace(envelope=str(env),operation_id=op,migration_key=op,project_id='p1',branch_id='b1',logical_memory_id='m1',inventory=inv,inventory_attestation=att,inventory_evidence_sha256=doc['snapshot_sha256'],admission_evidence=admp,admission_attestation=admatt,parent_id=m.R9B0_DRIVE_PARENT_ID)
            self.assertEqual(m._active_plan(args(None))['status'],'OUTCOME_UNKNOWN')
            stale=root/'stale.json'; stale.write_text(json.dumps(make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op,age_seconds=600,valid_for_seconds=60)))
            self.assertEqual(m._active_plan(args(str(stale)))['status'],'OUTCOME_UNKNOWN')
            fresh=root/'fresh.json'; fresh.write_text(json.dumps(make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op)))
            self.assertEqual(m._active_plan(args(str(fresh)))['status'],'CREATE')

    def test_strict_json_rejects_duplicate_nonfinite_and_bool_integer_candidates(self):
        m=load_helper()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
                f=root/'x.json'; f.write_text(text)
                with self.subTest(text=text):
                    with self.assertRaises(ValueError): m._load_json(str(f))
            sha='0'*64; rel=f'active/p/b/m/{sha}.memory-epoch.json'
            c=make_candidate(operation_id='op',sha256=sha,byte_length=1,provider_locator='file',parent_id='parent',relative_path=rel,with_readback=False); c['byte_length']=True
            with self.assertRaises(ValueError): m.validate_candidate(c)

    def test_envelope_parse_is_closed_canonical_and_crossbound(self):
        m=load_helper(); raw,obj,op=make_envelope(m)
        parsed=m.parse_memory_epoch_envelope(raw); self.assertEqual(parsed['operation_id'],op)
        pretty=json.dumps(obj,indent=2).encode()
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(pretty)
        foreign=dict(obj); foreign['project_id']='other'; foreign_raw=json.dumps(foreign,sort_keys=True,separators=(',',':')).encode()
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(foreign_raw)
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(b'not-json')

    def test_operation_identity_is_exact_owner_tuple_and_embedded_op_must_match(self):
        m=load_helper(); raw,obj,op=make_envelope(m,source_version='source-v2',admission_generation='admit-v9')
        fields=['R9B0','p1','b1','m1','source-v2',obj['original']['sha256'],'admit-v9']; expected=hashlib.sha256(len(fields).to_bytes(4,'big')+b''.join(len(x.encode()).to_bytes(8,'big')+x.encode() for x in fields)).hexdigest()
        self.assertEqual(op,expected)
        bad=json.loads(raw); bad['migration']['operation_id']='forged'; badraw=json.dumps(bad,sort_keys=True,separators=(',',':')).encode()
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(badraw)

    def test_global_same_operation_multilocators_conflict_before_reuse(self):
        m=load_helper(); raw,obj,op=make_envelope(m); sha=hashlib.sha256(raw).hexdigest(); parent=m.R9B0_DRIVE_PARENT_ID; rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
        exact=make_candidate(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file-a',parent_id=parent,relative_path=rel)
        elsewhere=make_candidate(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file-b',parent_id=parent,relative_path='active/p1/b1/m1/other.memory-epoch.json')
        r=m.classify_candidates([exact,elsewhere],op,sha,len(raw),expected_parent_id=parent,expected_relative_path=rel)
        self.assertEqual(r['status'],'CONFLICT'); self.assertEqual(r['reason'],'RESERVED_OPERATION_IDENTITY_MULTIPLE')

    def test_reuse_requires_independent_exact_provider_readback_evidence(self):
        m=load_helper(); raw,obj,op=make_envelope(m); sha=hashlib.sha256(raw).hexdigest(); parent=m.R9B0_DRIVE_PARENT_ID; rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
        unverified=make_candidate(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='nonexistent://never-read',parent_id=parent,relative_path=rel,with_readback=False)
        r=m.classify_candidates([unverified],op,sha,len(raw),expected_parent_id=parent,expected_relative_path=rel)
        self.assertEqual(r['status'],'OUTCOME_UNKNOWN'); self.assertEqual(r['reason'],'EXACT_REUSE_READBACK_NOT_VERIFIED')
        verified=make_candidate(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file-real',parent_id=parent,relative_path=rel)
        self.assertEqual(m.classify_candidates([verified],op,sha,len(raw),expected_parent_id=parent,expected_relative_path=rel)['status'],'VERIFIED_REUSE')

    def test_active_readback_requires_provider_revision_operation_and_current_observation(self):
        m=load_helper(); raw,obj,op=make_envelope(m); sha=hashlib.sha256(raw).hexdigest(); parent=m.R9B0_DRIVE_PARENT_ID; rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
        ev=make_readback_evidence(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file-1',provider_revision='rev-7',parent_id=parent,relative_path=rel); att=make_attestation(ev['evidence_sha256'],'ACTIVE_PROVIDER_READBACK')
        self.assertEqual(m.verify_active_readback(raw,io.BytesIO(raw),ev,att,expected_evidence_sha256=ev['evidence_sha256'])['status'],'VERIFIED_EXACT')
        for field,value in [('operation_id','wrong'),('provider_revision',''),('currentness_status','STALE'),('sha256','0'*64)]:
            bad=dict(ev); bad[field]=value; bad['evidence_sha256']=_digest_doc(bad,'evidence_sha256'); badatt=make_attestation(bad['evidence_sha256'],'ACTIVE_PROVIDER_READBACK')
            with self.subTest(field=field): self.assertNotEqual(m.verify_active_readback(raw,io.BytesIO(raw),bad,badatt,expected_evidence_sha256=ev['evidence_sha256'])['status'],'VERIFIED_EXACT')

    def test_archive_readback_requires_bundle_entry_locator_and_verified_receipt_graph(self):
        m=load_helper(); original=b'archive-provenance'; sha=hashlib.sha256(original).hexdigest(); provenance=dict(logical_memory_id='m',generation_id='g',predecessor_generation='p',predecessor_container_sha256='1'*64,subject_id='s',admission_receipt_id='a',supabase_receipt_id='u',drive_receipt_id='d',operation_id='o')
        archive=m.build_archive_generation(**provenance,original_bytes=original,original_sha256=sha); csha=hashlib.sha256(archive).hexdigest(); entry=f'memories/m/{sha}/original.bin'
        ev=make_archive_evidence(archive_bundle_locator='drive://bundle-1',archive_entry_locator=entry,provider_revision='rev-1',archive_container_sha256=csha,archive_container_byte_length=len(archive),original_sha256=sha,original_byte_length=len(original),generation_id=provenance['generation_id'],subject_id=provenance['subject_id'],admission_receipt_id=provenance['admission_receipt_id'],supabase_receipt_id=provenance['supabase_receipt_id'],drive_receipt_id=provenance['drive_receipt_id'],operation_id=provenance['operation_id'])
        att=make_attestation(ev['evidence_sha256'],'ARCHIVE_PROVIDER_READBACK')
        r=m.verify_archive_readback_with_evidence(archive,original,ev,att,expected_container_sha256=csha,expected_container_byte_length=len(archive),expected_evidence_sha256=ev['evidence_sha256'],**provenance,original_sha256=sha)
        self.assertEqual(r['status'],'VERIFIED_EXACT')
        for field in ('archive_bundle_locator','archive_entry_locator','supabase_receipt_id'):
            bad=dict(ev); bad[field]='fake'; bad['evidence_sha256']=_digest_doc(bad,'evidence_sha256'); badatt=make_attestation(bad['evidence_sha256'],'ARCHIVE_PROVIDER_READBACK')
            with self.subTest(field=field): self.assertNotEqual(m.verify_archive_readback_with_evidence(archive,original,bad,badatt,expected_container_sha256=csha,expected_container_byte_length=len(archive),expected_evidence_sha256=ev['evidence_sha256'],**provenance,original_sha256=sha)['status'],'VERIFIED_EXACT')

    def test_active_plan_requires_detached_trusted_inventory_digest_anchor(self):
        m=load_helper()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); raw,obj,op=make_envelope(m); env=root/'e.json'; env.write_bytes(raw); sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
            doc=make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op); inv=write_doc(root,'i.json',doc)
            admission=make_admission_evidence(raw,obj,op); admp=write_doc(root,'admission.json',admission); admatt=write_doc(root,'admission.att.json',make_attestation(admission['evidence_sha256'],'ACTIVE_DUPLICATION_ADMISSION'))
            base=dict(envelope=str(env),operation_id=op,migration_key=op,project_id='p1',branch_id='b1',logical_memory_id='m1',inventory=inv,inventory_evidence_sha256=doc['snapshot_sha256'],admission_evidence=admp,admission_attestation=admatt,parent_id=m.R9B0_DRIVE_PARENT_ID)
            self.assertEqual(m._active_plan(types.SimpleNamespace(**base,inventory_attestation=None))['status'],'OUTCOME_UNKNOWN')
            forged=make_attestation(doc['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT'); forged['signature_base64']=base64.b64encode(b'0'*256).decode(); fp=write_doc(root,'forged.att.json',forged)
            self.assertEqual(m._active_plan(types.SimpleNamespace(**base,inventory_attestation=fp))['status'],'OUTCOME_UNKNOWN')
            good=write_doc(root,'good.att.json',make_attestation(doc['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT'))
            self.assertEqual(m._active_plan(types.SimpleNamespace(**base,inventory_attestation=good))['status'],'CREATE')

    def test_inventory_snapshot_attests_path_and_global_operation_scope(self):
        m=load_helper(); raw,obj,op=make_envelope(m); sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
        good=make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op); att=make_attestation(good['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT')
        self.assertEqual(m.validate_inventory_snapshot(good,expected_parent_id=m.R9B0_DRIVE_PARENT_ID,expected_relative_path=rel,expected_operation_id=op,authority_attestation=att,expected_evidence_sha256=good['snapshot_sha256']),[])
        for field,value in [('path_scope_complete',False),('operation_scope_complete',False),('locator_scope_complete',False),('operation_id','other'),('currentness_status','STALE'),('verifier_route','CALLER_SELF_ASSERTED')]:
            bad=dict(good); bad[field]=value; bad['snapshot_sha256']=_digest_doc(bad,'snapshot_sha256'); badatt=make_attestation(bad['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT')
            with self.subTest(field=field):
                with self.assertRaises(ValueError): m.validate_inventory_snapshot(bad,expected_parent_id=m.R9B0_DRIVE_PARENT_ID,expected_relative_path=rel,expected_operation_id=op,authority_attestation=badatt,expected_evidence_sha256=good['snapshot_sha256'])

    def test_standalone_readback_requires_trusted_evidence_digest_anchor(self):
        m=load_helper(); raw,obj,op=make_envelope(m); sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'
        ev=make_readback_evidence(operation_id=op,sha256=sha,byte_length=len(raw),provider_locator='file',provider_revision='rev',parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel)
        r=m.verify_active_readback(raw,io.BytesIO(raw),ev)
        self.assertEqual(r['status'],'MISMATCH'); self.assertEqual(r['reason'],'READBACK_EVIDENCE_INVALID')

    def test_non_nfc_envelope_string_is_noncanonical(self):
        m=load_helper(); raw,obj,op=make_envelope(m); bad=json.loads(raw); bad['provenance']['source_actor']='e\u0301'; badraw=json.dumps(bad,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(badraw)

    def test_local_archive_output_rejects_symlink_hardlink_and_create_race(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); target=root/'target'; target.write_bytes(b'original')
            link=root/'link'; link.symlink_to(target)
            r=m.create_or_verify_local_archive(link,archive); self.assertEqual(r['status'],'CONFLICT'); self.assertEqual(target.read_bytes(),b'original')
            real=root/'real'; real.write_bytes(archive); hard=root/'hard'; os.link(real,hard)
            r=m.create_or_verify_local_archive(hard,archive); self.assertEqual(r['status'],'CONFLICT')
            fresh=root/'fresh';
            original_open=os.open
            def racing_open(path,flags,*a,**kw):
                if path=='fresh' and flags & os.O_CREAT: raise FileExistsError('race')
                return original_open(path,flags,*a,**kw)
            with mock.patch.object(m.os,'open',side_effect=racing_open):
                r=m.create_or_verify_local_archive(fresh,archive)
            self.assertEqual(r['status'],'CONFLICT'); self.assertEqual(r['reason'],'LOCAL_ARCHIVE_CREATE_RACE')

    def test_019_self_hashed_detached_evidence_cannot_self_authorize(self):
        m=load_helper(); doc={'x':'caller-controlled'}; digest=hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        forged=make_attestation(digest,'DRIVE_INVENTORY_SNAPSHOT'); forged['signature_base64']=base64.b64encode(b'\x01'*256).decode()
        with self.assertRaises(ValueError): m.validate_authority_attestation(forged,expected_evidence_sha256=digest,expected_purpose='DRIVE_INVENTORY_SNAPSHOT')

    def test_020_active_create_blocks_forbidden_privacy_and_tombstoned_lifecycle(self):
        m=load_helper()
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            for field,value in [('privacy_scope','PRIVATE_FORBIDDEN_TO_DUPLICATE'),('lifecycle','TOMBSTONED')]:
                raw,obj,op=make_envelope(m); obj['governance'][field]=value; raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode(); env=write_doc(root,'e.json',json.loads(raw))
                sha=hashlib.sha256(raw).hexdigest(); rel=f'active/p1/b1/m1/{sha}.memory-epoch.json'; inv=make_inventory([],parent_id=m.R9B0_DRIVE_PARENT_ID,relative_path=rel,operation_id=op)
                invp=write_doc(root,'inv.json',inv); invatt=write_doc(root,'inv.att.json',make_attestation(inv['snapshot_sha256'],'DRIVE_INVENTORY_SNAPSHOT'))
                adm=make_admission_evidence(raw,obj,op); admp=write_doc(root,'adm.json',adm); admatt=write_doc(root,'adm.att.json',make_attestation(adm['evidence_sha256'],'ACTIVE_DUPLICATION_ADMISSION'))
                args=types.SimpleNamespace(envelope=env,operation_id=op,migration_key=op,project_id='p1',branch_id='b1',logical_memory_id='m1',inventory=invp,inventory_attestation=invatt,inventory_evidence_sha256=inv['snapshot_sha256'],admission_evidence=admp,admission_attestation=admatt,parent_id=m.R9B0_DRIVE_PARENT_ID)
                with self.subTest(field=field):
                    r=m._active_plan(args); self.assertEqual(r['status'],'BLOCKED_EVIDENCE'); self.assertEqual(r['reason'],'ACTIVE_DUPLICATION_NOT_ELIGIBLE')

    def test_021_archive_effect_requires_verifier_rooted_dual_active_readback(self):
        m=load_helper(); original=b'dual-readback-source'; raw,obj,op=make_envelope(m,logical_memory_id='m',original=original); sha=obj['original']['sha256']; admission='adm-r'; sup='sup-r'; drv='drv-r'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); original_path=root/'original.bin'; original_path.write_bytes(original); envelope_path=root/'envelope.json'; envelope_path.write_bytes(raw); output=root/'archive.tgz'
            common=dict(operation_id=op,logical_memory_id='m',original_sha256=sha,original_byte_length=len(original),admission_receipt_id=admission,envelope_sha256=hashlib.sha256(raw).hexdigest(),envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'])
            se=make_active_store_readback(provider_class='SUPABASE_RUNTIME',provider_receipt_id=sup,locator='supabase://row',provider_identity='supabase-project-r9b0',**common)
            de=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id=drv,locator='drive://file',provider_identity='drive-parent-r9b0',**common)
            sep=write_doc(root,'se.json',se); dep=write_doc(root,'de.json',de)
            satt=make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'); satt['signature_base64']=base64.b64encode(b'\x02'*256).decode()
            sattp=write_doc(root,'se.att.json',satt); datt=write_doc(root,'de.att.json',make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE'))
            argv=['create-or-verify-archive-generation','--envelope',str(envelope_path),'--original',str(original_path),'--output',str(output),'--logical-memory-id','m','--original-sha256',sha,'--generation-id','g','--predecessor-generation','p','--predecessor-container-sha256','1'*64,'--subject-id','s','--admission-receipt-id',admission,'--supabase-receipt-id',sup,'--drive-receipt-id',drv,'--operation-id',op,'--supabase-readback-evidence',sep,'--supabase-readback-attestation',sattp,'--drive-readback-evidence',dep,'--drive-readback-attestation',datt]
            with mock.patch('builtins.print'):
                rc=m.main(argv)
            self.assertEqual(rc,2); self.assertFalse(output.exists())

    def test_022_provider_locator_cannot_bind_contradictory_identities(self):
        m=load_helper(); sha='0'*64; rel='active/p/b/m/'+sha+'.memory-epoch.json'; parent='parent'
        a=make_candidate(operation_id='op-a',sha256=sha,byte_length=1,provider_locator='same-locator',parent_id=parent,relative_path=rel)
        b=make_candidate(operation_id='op-b',sha256='1'*64,byte_length=2,provider_locator='same-locator',parent_id='other',relative_path='active/p/b/m/other.memory-epoch.json')
        r=m.classify_candidates([a,b],'op-a',sha,1,expected_parent_id=parent,expected_relative_path=rel)
        self.assertEqual(r['status'],'CONFLICT'); self.assertEqual(r['reason'],'PROVIDER_LOCATOR_IDENTITY_MULTIBINDING')

    def test_023_envelope_rejects_noncanonical_base64_pad_bits(self):
        m=load_helper(); raw,obj,op=make_envelope(m,original=b'\xff')
        self.assertEqual(obj['original']['bytes_base64'],'/w==')
        obj['original']['bytes_base64']='/x=='
        alias=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
        with self.assertRaises(ValueError): m.parse_memory_epoch_envelope(alias)

    def test_024_reuse_detects_pathname_replacement_after_exact_fd_read(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); target=root/'archive'; target.write_bytes(archive); replacement=root/'replacement'; replacement.write_bytes(b'evil')
            original_stat=m.os.stat; calls={'n':0}
            def racing_stat(path,*a,**kw):
                if path=='archive' and kw.get('dir_fd') is not None:
                    calls['n']+=1
                    if calls['n']==2 and replacement.exists(): os.replace(replacement,target)
                return original_stat(path,*a,**kw)
            with mock.patch.object(m.os,'stat',side_effect=racing_stat):
                r=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(r['status'],'CONFLICT'); self.assertEqual(r['reason'],'LOCAL_ARCHIVE_PATH_REPLACED')

    def test_024_create_detects_pathname_replacement_as_incomplete_effect(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); target=root/'archive'; replacement=root/'replacement'; replacement.write_bytes(b'evil'); original_fsync=m.os.fsync
            fired={'v':False}
            def racing_fsync(fd):
                original_fsync(fd)
                if not fired['v']:
                    fired['v']=True; os.replace(replacement,target)
            with mock.patch.object(m.os,'fsync',side_effect=racing_fsync):
                r=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(r['status'],'MIGRATION_INCOMPLETE'); self.assertTrue(r['provider_effect_performed']); self.assertEqual(r['reason'],'LOCAL_ARCHIVE_PATH_REPLACED')

    def test_025_local_archive_resource_cap_blocks_before_file_effect(self):
        m=load_helper(); tight=dict(m.resolve_current_resource_profile(),profile_id='TIGHT_LOCAL_ARCHIVE',max_archive_member_expanded_bytes=8,max_archive_generation_expanded_bytes=8)
        reg={tight['profile_id']:tight}; binding={'schema':m.RESOURCE_PROFILE_BINDING_SCHEMA,'profile_id':tight['profile_id'],'profile_sha256':m.resource_profile_sha256(tight)}
        with tempfile.TemporaryDirectory() as td, mock.patch.object(m,'RESOURCE_PROFILE_REGISTRY',reg), mock.patch.object(m,'MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT',binding):
            target=pathlib.Path(td)/'archive'; r=m.create_or_verify_local_archive(target,b'123456789')
            self.assertEqual(r['status'],'BLOCKED_RESOURCE_LIMIT'); self.assertEqual(r['reason'],'ARCHIVE_CONTAINER_BYTES_EXCEEDED'); self.assertFalse(target.exists())

    def test_adjacent_attestation_purpose_and_dual_provider_binding_fail_closed(self):
        m=load_helper(); evidence_sha='0'*64; att=make_attestation(evidence_sha,'ACTIVE_PROVIDER_READBACK')
        with self.assertRaises(ValueError): m.validate_authority_attestation(att,expected_evidence_sha256=evidence_sha,expected_purpose='DRIVE_INVENTORY_SNAPSHOT')
        common=dict(operation_id='o',envelope_sha256='0'*64,envelope_byte_length=1,project_id='p',branch_id='b',epoch_id='R9B0',logical_memory_id='m',original_sha256='1'*64,original_byte_length=1,admission_generation='admit-v1',admission_metadata_sha256='2'*64,admission_receipt_id='a')
        se=make_active_store_readback(provider_class='SUPABASE_DURABLE',provider_receipt_id='u',locator='same',**common)
        de=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id='d',locator='same',**common)
        with self.assertRaises(ValueError):
            m.validate_dual_active_readback_evidence(se,make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'),de,make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE'),supabase_receipt_id='u',drive_receipt_id='d',**common)



    def test_adjacent_create_detects_parent_path_replacement_as_incomplete_effect(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); parent=root/'parent'; parent.mkdir(); target=parent/'archive'; old=root/'old-parent'; original_fsync=m.os.fsync
            fired={'v':False}
            def racing_fsync(fd):
                original_fsync(fd)
                if not fired['v']:
                    fired['v']=True
                    os.rename(parent,old)
                    parent.mkdir()
            with mock.patch.object(m.os,'fsync',side_effect=racing_fsync):
                r=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(r['status'],'MIGRATION_INCOMPLETE')
            self.assertTrue(r['provider_effect_performed'])
            self.assertEqual(r['reason'],'LOCAL_ARCHIVE_PARENT_PATH_REPLACED')
            self.assertFalse(target.exists())
            self.assertTrue((old/'archive').exists())


    def test_026_parent_directory_identity_positive_create_and_reuse(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); parent=root/'parent'; parent.mkdir(); target=parent/'archive'
            pfd=m._open_parent_dir_nofollow(parent,create=False)
            try:
                self.assertTrue(m._verify_parent_dir_current_path(parent,pfd))
            finally:
                os.close(pfd)
            first=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(first['status'],'CREATE')
            self.assertEqual(target.read_bytes(),archive)
            second=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(second['status'],'VERIFIED_REUSE')
            self.assertFalse(second['provider_effect_performed'])

    def test_027_dual_readback_binds_full_envelope_and_accepts_supabase_runtime(self):
        m=load_helper(); raw1,obj1,op=make_envelope(m,project_id='p1',branch_id='b1',logical_memory_id='m1',original=b'abc')
        obj2=json.loads(raw1); obj2['indexing']['tags']=['different-indexing']; raw2=json.dumps(obj2,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        self.assertEqual(obj2['migration']['operation_id'],op); self.assertNotEqual(hashlib.sha256(raw1).hexdigest(),hashlib.sha256(raw2).hexdigest())
        def evidence(provider_class, provider_identity, locator, provider_receipt):
            now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            d={
                'schema':'R9B0_ACTIVE_STORE_READBACK_EVIDENCE_V1','status':'VERIFIED_EXACT',
                'provider_class':provider_class,'provider_identity':provider_identity,'provider_locator':locator,'provider_revision':'rev-current',
                'operation_id':op,'envelope_sha256':hashlib.sha256(raw1).hexdigest(),'envelope_byte_length':len(raw1),
                'project_id':'p1','branch_id':'b1','epoch_id':'R9B0','logical_memory_id':'m1',
                'original_sha256':obj1['original']['sha256'],'original_byte_length':obj1['original']['byte_length'],
                'admission_generation':obj1['migration']['admission_generation'],'admission_metadata_sha256':obj1['migration']['admission_metadata_sha256'],
                'admission_receipt_id':'adm-r','provider_receipt_id':provider_receipt,'receipt_id':'readback-'+provider_class,
                'observation_id':'obs-'+provider_class,'observed_at':now.isoformat().replace('+00:00','Z'),
                'valid_until':(now+dt.timedelta(seconds=240)).isoformat().replace('+00:00','Z'),'currentness_status':'VERIFIED_CURRENT','evidence_sha256':''
            }
            d['evidence_sha256']=_digest_doc(d,'evidence_sha256'); return d
        se=evidence('SUPABASE_RUNTIME','supabase-project-r9b0','supabase://runtime/row','sup-r')
        de=evidence('GOOGLE_DRIVE_DURABLE','drive-parent-r9b0','drive://file','drv-r')
        satt=make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'); datt=make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE')
        common=dict(operation_id=op,envelope_sha256=hashlib.sha256(raw1).hexdigest(),envelope_byte_length=len(raw1),project_id='p1',branch_id='b1',epoch_id='R9B0',logical_memory_id='m1',original_sha256=obj1['original']['sha256'],original_byte_length=obj1['original']['byte_length'],admission_generation=obj1['migration']['admission_generation'],admission_metadata_sha256=obj1['migration']['admission_metadata_sha256'],admission_receipt_id='adm-r',supabase_receipt_id='sup-r',drive_receipt_id='drv-r')
        ok=m.validate_dual_active_readback_evidence(se,satt,de,datt,**common)
        self.assertEqual(ok['supabase']['provider_class'],'SUPABASE_RUNTIME')
        hostile=dict(common,envelope_sha256=hashlib.sha256(raw2).hexdigest(),envelope_byte_length=len(raw2))
        with self.assertRaises(ValueError):
            m.validate_dual_active_readback_evidence(se,satt,de,datt,**hostile)

    def test_028_signed_supabase_durable_active_replica_role_is_rejected(self):
        m=load_helper(); raw,obj,op=make_envelope(m,project_id='p1',branch_id='b1',logical_memory_id='m1',original=b'abc'); envsha=hashlib.sha256(raw).hexdigest()
        common=dict(operation_id=op,envelope_sha256=envsha,envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',logical_memory_id='m1',original_sha256=obj['original']['sha256'],original_byte_length=obj['original']['byte_length'],admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'],admission_receipt_id='a')
        se=make_active_store_readback(provider_class='SUPABASE_DURABLE',provider_receipt_id='u',locator='supabase://durable/row',provider_identity='sup-id',**common)
        de=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id='d',locator='drive://file',provider_identity='drv-id',**common)
        satt=make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'); datt=make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE')
        with self.assertRaises(ValueError):
            m.validate_dual_active_readback_evidence(se,satt,de,datt,supabase_receipt_id='u',drive_receipt_id='d',**common)

    def test_028_adjacent_low_level_readback_validator_cannot_accept_caller_broadened_role_set(self):
        m=load_helper(); raw,obj,op=make_envelope(m,project_id='p1',branch_id='b1',logical_memory_id='m1',original=b'abc'); envsha=hashlib.sha256(raw).hexdigest()
        common=dict(operation_id=op,envelope_sha256=envsha,envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',logical_memory_id='m1',original_sha256=obj['original']['sha256'],original_byte_length=obj['original']['byte_length'],admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'],admission_receipt_id='a',provider_receipt_id='u')
        bad=make_active_store_readback(provider_class='SUPABASE_DURABLE',locator='supabase://durable/row',provider_identity='sup-id',**common)
        with self.assertRaises(ValueError):
            m.validate_active_store_readback_evidence(bad,make_attestation(bad['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'),expected_purpose='ACTIVE_STORE_READBACK_SUPABASE',**common)

    def test_028_adjacent_active_replica_role_aliases_and_cross_provider_roles_are_rejected(self):
        m=load_helper(); raw,obj,op=make_envelope(m,project_id='p1',branch_id='b1',logical_memory_id='m1',original=b'abc'); envsha=hashlib.sha256(raw).hexdigest()
        common=dict(operation_id=op,envelope_sha256=envsha,envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',logical_memory_id='m1',original_sha256=obj['original']['sha256'],original_byte_length=obj['original']['byte_length'],admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'],admission_receipt_id='a')
        good_s=make_active_store_readback(provider_class='SUPABASE_RUNTIME',provider_receipt_id='u',locator='supabase://runtime/row',provider_identity='sup-id',**common)
        good_d=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id='d',locator='drive://file',provider_identity='drv-id',**common)
        for bad_role in ('SUPABASE_DURABLE','SUPABASE_ARCHIVE','GOOGLE_DRIVE_DURABLE'):
            bad_s=make_active_store_readback(provider_class=bad_role,provider_receipt_id='u',locator='supabase://bad/row',provider_identity='sup-bad',**common)
            with self.subTest(supabase_role=bad_role), self.assertRaises(ValueError):
                m.validate_dual_active_readback_evidence(bad_s,make_attestation(bad_s['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'),good_d,make_attestation(good_d['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE'),supabase_receipt_id='u',drive_receipt_id='d',**common)
        bad_d=make_active_store_readback(provider_class='SUPABASE_RUNTIME',provider_receipt_id='d',locator='drive://bad',provider_identity='drv-bad',**common)
        with self.assertRaises(ValueError):
            m.validate_dual_active_readback_evidence(good_s,make_attestation(good_s['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'),bad_d,make_attestation(bad_d['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE'),supabase_receipt_id='u',drive_receipt_id='d',**common)

    def test_027_archive_cli_full_envelope_supabase_runtime_positive_create_reuse(self):
        m=load_helper(); original=b'archive-positive'; raw,obj,op=make_envelope(m,logical_memory_id='m',original=original); sha=obj['original']['sha256']; admission='adm-positive'; sup='sup-positive'; drv='drv-positive'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); original_path=root/'original.bin'; original_path.write_bytes(original); envelope_path=root/'envelope.json'; envelope_path.write_bytes(raw); output=root/'archive.tgz'
            common=dict(operation_id=op,logical_memory_id='m',original_sha256=sha,original_byte_length=len(original),admission_receipt_id=admission,envelope_sha256=hashlib.sha256(raw).hexdigest(),envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'])
            se=make_active_store_readback(provider_class='SUPABASE_RUNTIME',provider_receipt_id=sup,locator='supabase://runtime/row',provider_identity='supabase-runtime-project',**common)
            de=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id=drv,locator='drive://file',provider_identity='drive-durable-parent',**common)
            sep=write_doc(root,'se.json',se); dep=write_doc(root,'de.json',de); sattp=write_doc(root,'se.att.json',make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE')); dattp=write_doc(root,'de.att.json',make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE'))
            argv=['create-or-verify-archive-generation','--envelope',str(envelope_path),'--original',str(original_path),'--output',str(output),'--logical-memory-id','m','--original-sha256',sha,'--generation-id','g','--predecessor-generation','p','--predecessor-container-sha256','1'*64,'--subject-id','s','--admission-receipt-id',admission,'--supabase-receipt-id',sup,'--drive-receipt-id',drv,'--operation-id',op,'--supabase-readback-evidence',sep,'--supabase-readback-attestation',sattp,'--drive-readback-evidence',dep,'--drive-readback-attestation',dattp]
            with mock.patch('builtins.print'):
                self.assertEqual(m.main(argv),0)
                self.assertTrue(output.exists())
                first=output.read_bytes()
                self.assertEqual(m.main(argv),0)
                self.assertEqual(output.read_bytes(),first)

    def test_027_dual_readback_rejects_each_full_envelope_identity_mismatch_and_same_provider_identity(self):
        m=load_helper(); raw,obj,op=make_envelope(m,project_id='p1',branch_id='b1',logical_memory_id='m1',original=b'abc'); envsha=hashlib.sha256(raw).hexdigest()
        common=dict(operation_id=op,envelope_sha256=envsha,envelope_byte_length=len(raw),project_id='p1',branch_id='b1',epoch_id='R9B0',logical_memory_id='m1',original_sha256=obj['original']['sha256'],original_byte_length=obj['original']['byte_length'],admission_generation=obj['migration']['admission_generation'],admission_metadata_sha256=obj['migration']['admission_metadata_sha256'],admission_receipt_id='a')
        se=make_active_store_readback(provider_class='SUPABASE_RUNTIME',provider_receipt_id='u',locator='supabase://row',provider_identity='sup-id',**common); de=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id='d',locator='drive://file',provider_identity='drv-id',**common)
        satt=make_attestation(se['evidence_sha256'],'ACTIVE_STORE_READBACK_SUPABASE'); datt=make_attestation(de['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE')
        base=dict(common,supabase_receipt_id='u',drive_receipt_id='d')
        bad={
            'operation_id':'different-op','envelope_sha256':'f'*64,'envelope_byte_length':len(raw)+1,'project_id':'p2','branch_id':'b2','epoch_id':'R9C0','logical_memory_id':'m2','original_sha256':'e'*64,'original_byte_length':obj['original']['byte_length']+1,'admission_generation':'other-admit','admission_metadata_sha256':'d'*64,
        }
        for field,value in bad.items():
            args=dict(base); args[field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.validate_dual_active_readback_evidence(se,satt,de,datt,**args)
        de_same=make_active_store_readback(provider_class='GOOGLE_DRIVE_DURABLE',provider_receipt_id='d',locator='drive://other',provider_identity='sup-id',**common); datt_same=make_attestation(de_same['evidence_sha256'],'ACTIVE_STORE_READBACK_DRIVE')
        with self.assertRaises(ValueError):
            m.validate_dual_active_readback_evidence(se,satt,de_same,datt_same,**base)

    def test_adjacent_parent_replacement_after_directory_proof_is_caught_by_final_full_path_rebind(self):
        m=load_helper(); archive=b'archive-bytes'
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); parent=root/'parent'; parent.mkdir(); target=parent/'archive'; old=root/'old-parent'
            original_verify=m._verify_parent_dir_current_path; fired={'v':False}
            def replace_after_proof(parent_path,parent_fd):
                ok=original_verify(parent_path,parent_fd)
                if ok and not fired['v']:
                    fired['v']=True; os.rename(parent,old); parent.mkdir(); (parent/'archive').write_bytes(b'evil')
                return ok
            with mock.patch.object(m,'_verify_parent_dir_current_path',side_effect=replace_after_proof):
                r=m.create_or_verify_local_archive(target,archive)
            self.assertEqual(r['status'],'MIGRATION_INCOMPLETE')
            self.assertEqual(r['reason'],'LOCAL_ARCHIVE_PATH_REPLACED')
            self.assertTrue(r['provider_effect_performed'])
            self.assertEqual((old/'archive').read_bytes(),archive)
            self.assertEqual((parent/'archive').read_bytes(),b'evil')

    def test_adjacent_production_verifier_trust_root_is_fail_closed_unconfigured(self):
        spec=importlib.util.spec_from_file_location('r9b0_memory_epoch_drive_unconfigured',HELPER)
        m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        self.assertEqual(m.EVIDENCE_TRUST_ROOT_STATE,'UNCONFIGURED')
        self.assertIsNone(m._EVIDENCE_RSA_N)
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        att={'schema':m.EVIDENCE_ATTESTATION_SCHEMA,'authority_id':m.EVIDENCE_AUTHORITY_ID,'key_id':m.EVIDENCE_KEY_ID,'purpose':'DRIVE_INVENTORY_SNAPSHOT','evidence_sha256':'0'*64,'issued_at':now.isoformat().replace('+00:00','Z'),'valid_until':(now+dt.timedelta(seconds=60)).isoformat().replace('+00:00','Z'),'nonce':'n','signature_base64':'AA=='}
        with self.assertRaisesRegex(ValueError,'trust root'):
            m.validate_authority_attestation(att,expected_evidence_sha256='0'*64,expected_purpose='DRIVE_INVENTORY_SNAPSHOT')
        with mock.patch('builtins.print') as pr:
            rc=m.main(['inspect','--inventory','nope','--inventory-attestation','nope','--expected-parent-id','p','--expected-relative-path','x','--operation-id','o','--expected-sha256','0'*64,'--expected-byte-length','1'])
        self.assertEqual(rc,2)
        self.assertIn('VERIFIER_TRUST_ROOT_UNCONFIGURED',pr.call_args.args[0])

if __name__=='__main__':unittest.main()
