from __future__ import annotations
import json,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
FIX=pathlib.Path(__file__).resolve().parent/'fixtures/anticipatory_pragmatics_v1'
AP=json.loads((ROOT/'project/VERA_R9A0_NATIVE_CONTRACT.json').read_text())['anticipatory_pragmatics']
def resolve(case):
    protected=set(AP['protected_axes']); eligible=[c for c in case['candidates'] if c.get('admissible_evidence_ids')]
    if any(set(c.get('protected_axis_changes',[])) & protected for c in eligible): return {'discard_all':True,'hints':{}}
    out={}
    for axis in AP['presentation_axes']:
        contenders=[]
        for cand in eligible:
            if cand.get('axis')!=axis: continue
            value=cand.get('value')
            if not isinstance(value,str) or not value: continue
            contenders.append((cand['authority_rank'],value,tuple(cand['admissible_evidence_ids'])))
        if not contenders: out[axis]='unset'; continue
        best_rank=min(x[0] for x in contenders); best=[x for x in contenders if x[0]==best_rank]; vals={x[1] for x in best}
        out[axis]=next(iter(vals)) if len(vals)==1 else 'unset'
    return {'discard_all':False,'hints':out}
class T(unittest.TestCase):
 def test_contract(self):
  self.assertTrue(AP['deterministic']); self.assertTrue(AP['turn_local']); self.assertTrue(AP['read_only']); self.assertFalse(AP['persistence_or_store_calls']); self.assertFalse(AP['paid_dependency']); self.assertFalse(AP['extra_inference_for_style']); self.assertFalse(AP['private_chain_of_thought_serialization']); self.assertFalse(AP['broad_personal_retrieval_solely_for_style']); self.assertTrue(AP['non_unset_hint_requires_admitted_evidence']); self.assertTrue(AP['assistant_generated_material_cannot_self_bootstrap']); self.assertEqual(AP['protected_divergence_result'],'DISCARD_ALL_HINTS')
 def test_fixtures(self):
  fs=sorted(FIX.glob('*.json')); self.assertEqual(len(fs),12)
  for p in fs:
   with self.subTest(p=p.name): self.assertEqual(resolve(json.loads(p.read_text())),json.loads(p.read_text())['expected'])
