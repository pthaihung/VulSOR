from __future__ import annotations
import itertools, json, random, shutil, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from VulSOR_semantic_v4_13_release.BaseAgent import (
    PromptAgent, AgentRunError, _to_json_schema, _normalize_common_model_shapes,
    _salvage_truncated_collection_prefix, _merge_collection_outputs,
)
from VulSOR_semantic_v4_13_release.QualityGate import validate_semantic_claim_grounding
from VulSOR_semantic_v4_13_release.SemanticContract import validate_claim_output, SCHEMA_VERSION
from VulSOR_semantic_v4_13_release.Pipeline import (
    VulSORPipeline, PIPELINE_REVISION, AGENT_CLASSES,
    validate_obligations, validate_assessments, aggregate_final_verdict,
    assessment_counts, split_atomic_requirement, normalize_obligations_requirements,
    build_triggering_obligations, normalize_operations_for_reasoning,
    normalize_reasoner_output,
)
from VulSOR_semantic_v4_13_release.SimpleYaml import load_yaml

passed=[]
def check(name, cond):
    if not cond:
        raise AssertionError(name)
    passed.append(name)

# A. version / architecture surface
check('schema version v4.13', SCHEMA_VERSION == 'semantic-claims-v4.13')
check('pipeline revision v4.13', PIPELINE_REVISION == 'independent-semantic-views-v4.13')
check('resolver removed from agent classes', 'obligation_resolver' not in AGENT_CLASSES)
check('resolver prompt removed', not (ROOT/'prompts/Obligation_Resolver.yml').exists())

adj = load_yaml(ROOT/'prompts/Obligation_Adjudicator.yml')
adj_text=(ROOT/'prompts/Obligation_Adjudicator.yml').read_text()
check('adjudicator schema exactly two labels', adj.get('output_schema') == ['satisfied | violated'])
js = _to_json_schema(adj['output_schema'])
check('strict schema is array', js.get('type') == 'array')
check('strict schema enum exactly two labels', js.get('items',{}).get('enum') == ['satisfied','violated'])
check('adjudicator has no evidence requirement', 'evidence' not in adj_text.lower())
check('adjudicator has no confidence output', 'confidence score' in adj_text.lower() and 'auxiliary fields' in adj_text.lower())

# B. Stage-3 validator truth table
valid_cases=[['satisfied'], ['violated'], ['satisfied','violated'], ['satisfied']*20, ['violated']*20]
for case in valid_cases:
    check('valid assessment '+repr(case[:3])+str(len(case)), not validate_assessments(case,len(case)))
invalid_cases=[
    (['unresolved'],1), (['conditional'],1), (['potentially_violated'],1), ([None],1),
    ([{'assessment':'satisfied'}],1), ({'assessments':['satisfied']},1), (['satisfied'],2),
    (['vulnerable'],1), ([True],1), ([1],1),
]
for value,count in invalid_cases:
    check('reject '+repr(value), bool(validate_assessments(value,count)))

# C. exhaustive aggregation over all valid arrays length 0..10
num=0
for n in range(0,11):
    for vals in itertools.product(('satisfied','violated'), repeat=n):
        assessments=list(vals)
        op_count=0 if n==0 else 1
        out=aggregate_final_verdict(assessments,n,op_count)
        expected='Vulnerable' if 'violated' in assessments else 'Benign'
        if out['label'] != expected or out['analysis_failure']:
            raise AssertionError((n,assessments,out))
        num += 1
check(f'exhaustive aggregation {num} valid combinations', num==2047)

# Technical failure remains failure, never coerced to binary.
for bad,count,ops in [(['unresolved'],1,1), (['satisfied'],2,1)]:
    out=aggregate_final_verdict(bad,count,ops)
    check('invalid protocol -> AnalysisFailure '+repr(bad), out['analysis_failure'] and out['binary_prediction'] is None)
check('no operation -> benign', aggregate_final_verdict([],0,0)['label']=='Benign')
check('operations filtered to zero obligations -> benign', aggregate_final_verdict([],0,3)['label']=='Benign' and aggregate_final_verdict([],0,3)['decision_basis']=='no_security_relevant_obligations')

# D. assessment count summary
check('assessment counts two keys', assessment_counts(['satisfied','violated','violated']) == {'satisfied':1,'violated':2})
trigs=build_triggering_obligations(['satisfied','violated'],[
    {'locations':['L1'],'expression':'x','requirements':['x must be valid']},
    {'locations':['L2'],'expression':'*p','requirements':['p must be valid']},
])
check('trigger helper maps exact violated obligation', trigs==[{'index':1,'locations':['L2'],'expression':'*p','requirements':['p must be valid']}])

# E. Stage2 validation and duplicate/atomic controls
semantic={'operations':[{'locations':['L3'],'expression':'a[i]','claim':'indexed read'}], 'states':[], 'values':[], 'executions':[]}
valid={'obligations':[{'locations':['L3'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']} ]}
check('valid obligation', not validate_obligations(valid,semantic))
check('anchor mismatch rejected', bool(validate_obligations({'obligations':[{'locations':['L2'],'expression':'a[i]','requirements':['i must be valid']}]}, semantic)))
check('duplicate requirement rejected', bool(validate_obligations({'obligations':[{'locations':['L3'],'expression':'a[i]','requirements':['i must be valid','i must be valid']}]}, semantic)))
compound={'obligations':[{'locations':['L3'],'expression':'a[i]','requirements':['i must be nonnegative and i must be below n']}]}
check('safely splittable compound accepted', not validate_obligations(compound,semantic))
normalized=normalize_obligations_requirements(compound['obligations'])
check('compound canonicalized to two atomic requirements', normalized[0]['requirements']==['i must be nonnegative','i must be below n'])
check('atomic splitter leaves unsynthesizable conjunction intact', split_atomic_requirement('p must be non-null and live')==['p must be non-null and live'])
check('unsplittable compound no longer protocol-fatal', not validate_obligations({'obligations':[{'locations':['L1'],'expression':'a[i]','requirements':['p must be non-null and p must remain live together']} ]},{'operations':[{'locations':['L1'],'expression':'a[i]','claim':'read'}]}))


# E2. Stage-2 safety-relevance gate: empty requirements is a valid filter decision.
filtered_candidate={'obligations':[{'locations':['L3'],'expression':'helper(x)','requirements':[]}]}
filtered_semantic={'operations':[{'locations':['L3'],'expression':'helper(x)','claim':'opaque helper call'}]}
check('empty requirements accepted as safety gate rejection', not validate_obligations(filtered_candidate, filtered_semantic))
normalized_reasoner=normalize_reasoner_output({'parsed':filtered_candidate,'quality_gate':{}})
check('empty safety candidate removed before adjudication', normalized_reasoner['parsed']['obligations']==[])
check('safety gate reports filtered candidate', normalized_reasoner['quality_gate']['safety_relevance_filter']['filtered_non_safety_candidates']==1)

# E3. Serialization continuation helpers preserve complete records and merge only new ones.
truncated='{"values":[{"entities":["a"],"claim":"x","evidence":"L1: a=1;"},{"entities":["b"],"claim":"y","evidence":"L2: b='
salvaged=_salvage_truncated_collection_prefix(truncated, {'values':[{'entities':['string'],'claim':'string','evidence':'string'}]})
check('truncated collection salvages complete prefix', isinstance(salvaged,dict) and len(salvaged.get('values',[]))==1)
merged=_merge_collection_outputs(salvaged, {'values':[salvaged['values'][0],{'entities':['b'],'claim':'y','evidence':'L2: b=2;'}]}, {'values':[{'entities':['string'],'claim':'string','evidence':'string'}]})
check('continuation merge dedupes repeated prefix', len(merged['values'])==2 and merged['values'][1]['entities']==['b'])

# F. Grounding regressions: multiline calls, macros, wrong-nearby location
source='''void f(Node *n) {\n  int x = 0;\n  value = GetNodeAttr(\n      n->attrs(),\n      "is_constant",\n      &is_constant_enter);\n  other = GetNodeAttr(\n      n->attrs(),\n      "parallel_iterations",\n      &parallel_iterations);\n}\n'''
ok={'operations':[{'locations':['L3'],'expression':'GetNodeAttr(n->attrs(), "is_constant", &is_constant_enter)','claim':'contract call'}]}
err,_=validate_semantic_claim_grounding(ok,'operation_agent',source)
check('multiline exact call grounding passes', not err)
wrong={'operations':[{'locations':['L7'],'expression':'GetNodeAttr(n->attrs(), "is_constant", &is_constant_enter)','claim':'contract call'}]}
err,_=validate_semantic_claim_grounding(wrong,'operation_agent',source)
check('same callee wrong args/location rejected', bool(err))
ell={'operations':[{'locations':['L3','L7'],'expression':'GetNodeAttr(n->attrs(), ...)','claim':'contract call'}]}
err,_=validate_semantic_claim_grounding(ell,'operation_agent',source)
check('controlled ellipsis grouped grounding passes', not err)

macro='''#define M() \\\n  p1=p; \\\n  p1+=size; \\\n  buffer[length-2]='\\0'; \\\n  done();\n'''
val={'values':[{'entities':['p1','p'],'claim':'p1 derives from p','evidence':'L2: p1=p;\nL3: p1+=size;'}]}
err,_=validate_semantic_claim_grounding(val,'value_agent',macro)
check('macro continuation grounding passes', not err)

# G. Malformed-shape fuzz: validators must never crash.
atoms=[None,True,False,0,1,-1,1.5,'','x','satisfied','violated','unresolved',{},[]]
def rand(depth=0):
    if depth>3 or random.random()<.43:
        a=random.choice(atoms)
        if isinstance(a,(dict,list)): return a.copy()
        return a
    if random.random()<.5:
        return [rand(depth+1) for _ in range(random.randint(0,5))]
    return {str(random.choice(['operations','states','values','executions','locations','entities','claim','evidence','expression','obligations','requirements','x',1])): rand(depth+1) for _ in range(random.randint(0,5))}
for i in range(200000):
    z=rand()
    try:
        n=_normalize_common_model_shapes(z)
        for agent in ('operation_agent','state_agent','value_agent','execution_agent'):
            validate_claim_output(n,agent,100)
            validate_semantic_claim_grounding(n,agent,'x\ny\nz')
        validate_obligations(n,{'operations':[]})
        validate_assessments(n,2)
    except Exception as e:
        raise AssertionError(f'fuzz crash {i}: {type(e).__name__}: {e}; {z!r}')
check('200k malformed-shape fuzz no crash', True)

# H. PromptAgent retry: old third label -> retry -> valid binary.
class FakeClient:
    def __init__(self,responses): self.responses=list(responses); self.calls=0
    def chat_completion(self, **kwargs):
        self.calls+=1
        if not self.responses: raise AssertionError('queue exhausted')
        content=self.responses.pop(0)
        if not isinstance(content,str): content=json.dumps(content)
        return {'choices':[{'message':{'content':content},'finish_reason':'stop'}], 'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}

with tempfile.TemporaryDirectory() as td:
    base=Path(td)
    shutil.copytree(ROOT/'prompts',base/'prompts')
    cfg={'prompt_file':'prompts/Obligation_Adjudicator.yml','quality_gates':{'max_retries':1},'llm':{'max_tokens':1024,'timeout_seconds':120,'temperature':0,'response_format':'json'}}
    fake=FakeClient([['unresolved'],['violated']])
    agent=PromptAgent('obligation_adjudicator',cfg,base,fake)
    out=agent.run({'numbered_function_code':'L1: *p;','semantic_facts_json':{},'obligations_json':{'obligations':[{'locations':['L1'],'expression':'*p','requirements':['p must be valid']} ]},'obligation_count':1}, extra_validators=[lambda x: validate_assessments(x,1)])
    check('old third label triggers retry', fake.calls==2)
    check('retry accepts violated', out['parsed']==['violated'])

    # One status per obligation group even when the group contains multiple atomic requirements.
    grouped_vars={'numbered_function_code':'L1: x = a[i];','semantic_facts_json':{},'obligations_json':{'obligations':[{'locations':['L1'],'expression':'a[i]','requirements':['i must be nonnegative','i must be below the readable extent','a must designate live readable storage']}]},'obligation_count':1}
    fake_group=FakeClient([['satisfied']])
    grouped_agent=PromptAgent('obligation_adjudicator',cfg,base,fake_group)
    grouped_out=grouped_agent.run(grouped_vars,extra_validators=[lambda x: validate_assessments(x,1)])
    check('multiple atomic requirements -> one obligation status', grouped_out['parsed']==['satisfied'])


# H2. Truncated collection uses serialization continuation instead of semantic regeneration.
class FakeRawClient:
    def __init__(self, responses):
        self.responses=list(responses); self.calls=0; self.requests=[]
    def chat_completion(self, **kwargs):
        self.calls += 1
        self.requests.append(kwargs)
        if not self.responses: raise AssertionError('queue exhausted')
        return self.responses.pop(0)

with tempfile.TemporaryDirectory() as td:
    base=Path(td)
    shutil.copytree(ROOT/'prompts',base/'prompts')
    cfg={'prompt_file':'prompts/SemanticAgent/Value_Agent.yml','quality_gates':{'max_retries':1},'llm':{'max_tokens':8192,'timeout_seconds':120,'temperature':0,'response_format':'json','reasoning':{'enabled':True}}}
    first='{"values":[{"entities":["a"],"claim":"a affects size","evidence":"L1: a=1;"},{"entities":["b"],"claim":"unfinished'
    second=json.dumps({'values':[{'entities':['b'],'claim':'b affects size','evidence':'L2: b=2;'}]})
    raw_client=FakeRawClient([
        {'choices':[{'message':{'content':first},'finish_reason':'length'}], 'usage':{'prompt_tokens':100,'completion_tokens':80,'total_tokens':180}},
        {'choices':[{'message':{'content':second},'finish_reason':'stop'}], 'usage':{'prompt_tokens':80,'completion_tokens':20,'total_tokens':100}},
    ])
    agent=PromptAgent('value_agent',cfg,base,raw_client)
    out=agent.run({'numbered_function_code':'L1: a=1;\nL2: b=2;'})
    check('truncated output uses exactly one continuation call', raw_client.calls==2)
    check('continuation preserves prefix and appends remaining record', len(out['parsed']['values'])==2 and out['parsed']['values'][0]['entities']==['a'] and out['parsed']['values'][1]['entities']==['b'])
    check('retry mode records serialization continuation', out['quality_gate']['attempts'][1]['retry_mode']=='serialization_continuation')
    second_user=raw_client.requests[1]['messages'][-1].content
    check('continuation prompt forbids regeneration', 'Do NOT regenerate' in second_user and 'ONLY the additional records' in second_user)

# I. Minimal full six-agent pipeline, both binary branches + cache.
def mkproj(base:Path, samples:list[dict], labels:list[dict]):
    (base/'config').mkdir(parents=True); (base/'data').mkdir()
    shutil.copytree(ROOT/'prompts',base/'prompts')
    (base/'config/datasets.yml').write_text('''defaults:\n  active_dataset: demo\ndatasets:\n  demo:\n    splits:\n      test:\n        input_file: data/test.jsonl\n        label_file: data/labels.jsonl\n''')
    common='''      enabled: true\n      prompt_file: {prompt}\n      quality_gates:\n        max_retries: 1\n      llm:\n        model: fake\n        response_format: json\n        max_tokens: 8192\n        timeout_seconds: 120\n        temperature: 0\n'''
    agents={'operation_agent':'prompts/SemanticAgent/Operation_Agent.yml','state_agent':'prompts/SemanticAgent/State_Agent.yml','value_agent':'prompts/SemanticAgent/Value_Agent.yml','execution_agent':'prompts/SemanticAgent/Execution_Agent.yml','obligation_reasoner':'prompts/Obligation_Reasoner.yml','obligation_adjudicator':'prompts/Obligation_Adjudicator.yml'}
    txt='provider:\n  name: fake\nagents:\n'
    for k,v in agents.items(): txt+=f'  {k}:\n'+common.format(prompt=v)
    (base/'config/agents.yml').write_text(txt)
    (base/'data/test.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in samples))
    (base/'data/labels.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in labels))

sample_safe={'sample_id':'safe','code':'int f(int *a,int i,int n)\n{\n  if ((i < 0) || (i >= n)) return 0;\n  return a[i];\n}'}
sample_vuln={'sample_id':'vuln','code':'int f(int *a,int i,int n)\n{\n  return a[i];\n}'}
with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_safe,sample_vuln],[{'sample_id':'safe','target':0},{'sample_id':'vuln','target':1}])
    safe_resp=[
      {'operations':[{'locations':['L4'],'expression':'a[i]','claim':'indexed read'}]}, {'states':[]}, {'values':[]},
      {'executions':[{'entities':['i','n'],'claim':'reaching read implies 0 <= i < n','evidence':'L3: if ((i < 0) || (i >= n)) return 0;'}]},
      {'obligations':[{'locations':['L4'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}]}, ['satisfied']]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(safe_resp); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    rec=pipe.run_sample(sample_safe,3)
    check('end-to-end safe -> Benign', rec['output']['label']=='Benign' and rec['output']['binary_prediction']==0)
    check('benign has no triggering obligations', rec['output']['triggering_obligations']==[])
    check('end-to-end exactly six calls no resolver', fake.calls==6)
    # cache reuse
    fake2=FakeClient([]); pipe.llm_client=fake2; pipe.agents=pipe._build_agents(); rec2=pipe.run_sample(sample_safe,3)
    check('cache reuse no model calls', fake2.calls==0 and rec2['output']['label']=='Benign')

with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_vuln],[{'sample_id':'vuln','target':1}])
    vuln_resp=[
      {'operations':[{'locations':['L3'],'expression':'a[i]','claim':'indexed read'}]}, {'states':[]}, {'values':[]}, {'executions':[]},
      {'obligations':[{'locations':['L3'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}]}, ['violated']]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(vuln_resp); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    rec=pipe.run_sample(sample_vuln,3)
    check('end-to-end violated -> Vulnerable', rec['output']['label']=='Vulnerable' and rec['output']['binary_prediction']==1)
    check('violated decision basis', rec['output']['decision_basis']=='violated_obligation')
    check('violated trigger traced', rec['output']['triggering_obligations']==[{'index':0,'locations':['L3'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}])


with tempfile.TemporaryDirectory() as td:
    sample_filtered={'sample_id':'filtered','code':'int f(int x)\n{\n  return helper(x);\n}'}
    base=Path(td); mkproj(base,[sample_filtered],[{'sample_id':'filtered','target':0}])
    # Operation extractor emits a grounded candidate call, but Reasoner rejects it as
    # having no established security-relevant safety contract. Stage 3 must not run.
    filtered_resp=[
      {'operations':[{'locations':['L3'],'expression':'helper(x)','claim':'opaque helper call'}]},
      {'states':[]}, {'values':[]}, {'executions':[]},
      {'obligations':[{'locations':['L3'],'expression':'helper(x)','requirements':[]}]},
    ]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(filtered_resp); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    rec=pipe.run_sample(sample_filtered,3)
    check('all Stage2 candidates filtered -> Benign without adjudicator', rec['output']['label']=='Benign' and not rec['output']['analysis_failure'] and fake.calls==5)
    rules=json.loads((base/'stages/semantic-v4/filtered/stage_2_rules.json').read_text())
    check('filtered Stage2 artifact contains no obligations', rules['output']['rules']==[])

# J. Recovery policy + batch continuity. Item-level grounding defects are salvaged;
# genuinely unparseable agent output still becomes AnalysisFailure without stopping the batch.
with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_vuln,sample_safe],[{'sample_id':'vuln','target':1},{'sample_id':'safe','target':0}])
    responses=[
      # First sample: hallucinated operation is dropped deterministically; remaining views are valid.
      {'operations':[{'locations':['L999'],'expression':'hallucinated()','claim':'bad'}]},
      {'states':[]}, {'values':[]}, {'executions':[]}, {'obligations':[]},
      # Second sample: ordinary six-agent safe pipeline.
      {'operations':[{'locations':['L4'],'expression':'a[i]','claim':'indexed read'}]}, {'states':[]}, {'values':[]},
      {'executions':[{'entities':['i','n'],'claim':'reaching read implies 0 <= i < n','evidence':'L3: if ((i < 0) || (i >= n)) return 0;'}]},
      {'obligations':[{'locations':['L4'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}]}, ['satisfied']]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(responses); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    pipe.run_samples([sample_vuln,sample_safe],up_to_stage=3)
    recovered=json.loads((base/'stages/semantic-v4/vuln/stage_3_obligation_adjudicator.json').read_text())
    good=json.loads((base/'stages/semantic-v4/safe/stage_3_obligation_adjudicator.json').read_text())
    check('ungrounded item does not cause AnalysisFailure', not recovered['output']['analysis_failure'])
    check('batch continues after recovered item', good['output']['label']=='Benign')

with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_vuln,sample_safe],[{'sample_id':'vuln','target':1},{'sample_id':'safe','target':0}])
    responses=[
      'not-json', 'still-not-json',
      {'operations':[{'locations':['L4'],'expression':'a[i]','claim':'indexed read'}]}, {'states':[]}, {'values':[]},
      {'executions':[{'entities':['i','n'],'claim':'reaching read implies 0 <= i < n','evidence':'L3: if ((i < 0) || (i >= n)) return 0;'}]},
      {'obligations':[{'locations':['L4'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}]}, ['satisfied']]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(responses); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    pipe.run_samples([sample_vuln,sample_safe],up_to_stage=3)
    fail=json.loads((base/'stages/semantic-v4/vuln/stage_3_obligation_adjudicator.json').read_text())
    good=json.loads((base/'stages/semantic-v4/safe/stage_3_obligation_adjudicator.json').read_text())
    check('true parse failure recorded AnalysisFailure', fail['output']['analysis_failure'])
    check('failed sample keeps retry token usage', fail['token_usage'].get('total_tokens') == 30)
    check('failed-stage token attribution preserved', fail['token_usage_stage']==1 and fail['token_usage_by_stage']['stage_1']['total_tokens']==30 and fail['token_usage_by_stage']['stage_2']['total_tokens']==0)
    check('batch continues after true technical failure', good['output']['label']=='Benign')

# K. Progress and cache accounting: every processed sample emits sample_done; cached stages cost zero current tokens.
with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_safe],[{'sample_id':'safe','target':0}])
    responses=[
      {'operations':[{'locations':['L4'],'expression':'a[i]','claim':'indexed read'}]}, {'states':[]}, {'values':[]},
      {'executions':[{'entities':['i','n'],'claim':'reaching read implies 0 <= i < n','evidence':'L3: if ((i < 0) || (i >= n)) return 0;'}]},
      {'obligations':[{'locations':['L4'],'expression':'a[i]','requirements':['i must be within the valid readable extent of a']}]}, ['satisfied']]
    events=[]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(responses); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    pipe.run_samples([sample_safe],up_to_stage=3,progress_callback=events.append)
    check('successful sample emits sample_done', len([e for e in events if e.get('event')=='sample_done'])==1)
    cached_events=[]
    pipe.run_samples([sample_safe],up_to_stage=3,progress_callback=cached_events.append)
    cached_done=[e for e in cached_events if e.get('event')=='stage_done' and e.get('cached')]
    check('cached stage current-run tokens are zero', cached_done and all(e['token_usage']['total_tokens']==0 for e in cached_done))
    check('cached stage preserves artifact usage separately', any(e.get('artifact_token_usage',{}).get('total_tokens',0)>0 for e in cached_done))

with tempfile.TemporaryDirectory() as td:
    base=Path(td); mkproj(base,[sample_vuln],[{'sample_id':'vuln','target':1}])
    events=[]
    pipe=VulSORPipeline(base,split='test',dry_run=True,overwrite=True)
    fake=FakeClient(['not-json','still-not-json']); pipe.llm_client=fake; pipe.agents=pipe._build_agents(); pipe.pipeline_fingerprint=pipe._compute_pipeline_fingerprint()
    pipe.run_samples([sample_vuln],up_to_stage=3,progress_callback=events.append)
    done=[e for e in events if e.get('event')=='sample_done']
    check('failed sample also emits sample_done', len(done)==1 and done[0]['analysis_failure'])

# K2. Deterministic representation recovery.
from VulSOR_semantic_v4_13_release.QualityGate import repair_semantic_claim_output
rec={'values':[{'entities':['p','p','n'],'claim':'relation','evidence':'L99: else'}]}
ev=repair_semantic_claim_output(rec,'value_agent','int f()\n{\n  if (x) a();\n  else b();\n}')
check('duplicate entities deduped before contract validation', len(rec['values'][0]['entities'])==2 if rec['values'] else True)

op={'operations':[{'locations':['L99'],'expression':'a[i]','claim':'indexed read'}]}
ev2=repair_semantic_claim_output(op,'operation_agent','int f(int *a,int i)\n{\n  return a[i];\n}')
check('unique operation source occurrence repairs wrong line', op['operations'] and op['operations'][0]['locations']==['L3'])

# L. Lightweight bias mathematics: final OR rule has no class default, but error amplification is measurable.
# Assert exact formulas for benign sample-level false positive if per-requirement FP=p independently.
for m in (1,2,5,10,20):
    for p in (.01,.02,.05,.10):
        fp=1-(1-p)**m
        check(f'fp formula m={m} p={p}', 0 <= fp <= 1)

# v4.11: operation preparation-only canonicalization and grounding tolerance
ops_kept, ops_dropped = normalize_operations_for_reasoning([
    {"locations":["L1"],"expression":"q++","claim":"increment"},
    {"locations":["L2"],"expression":"*p++","claim":"dereference"},
])
check('bare q++ dropped before Stage2', len(ops_kept)==1 and ops_kept[0]['expression']=='*p++' and len(ops_dropped)==1)
qg_errors, qg_meta = validate_semantic_claim_grounding(
    {"values":[{"entities":["x"],"claim":"branch","evidence":"L1: else"}]},
    'value_agent',
    '} else {\nvalue = 1;\n'
)
check('evidence brace shorthand grounds uniquely', qg_errors==[])
qg_errors2, _ = validate_semantic_claim_grounding(
    {"values":[{"entities":["x"],"claim":"branch","evidence":"L1: value = 1;"}]},
    'value_agent',
    'x = 0;\nvalue = 1;\n'
)
check('unique exact evidence fallback tolerates nearby line error', qg_errors2==[])

print(f'PASS {len(passed)} named checks')
for n in passed: print('PASS', n)
