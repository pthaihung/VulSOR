# Semantic Claims V2 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. Execute sequentially unless the user explicitly requests delegation.

**Goal:** Chuyển bốn semantic agent và các consumer sang record `id, location, entities, claim, evidence` theo common rules của người dùng, bảo toàn khả năng truy vết bằng chứng.

**Architecture:** Stage 1 sinh semantic claims; Python xác thực contract và grounding rồi Stage 1.5 ghép claims theo entities/location bằng luật cố định. Stage 2 sinh obligations từ clusters và Stage 3 adjudicate bằng claims cùng evidence; output obligation/verdict giữ contract hiện tại. Metadata nội bộ nằm ngoài semantic record và artifact được version hóa để không reuse kết quả v1.

**Tech Stack:** Python, unittest, YAML prompts, SimpleYaml loader hiện tại, OpenAICompatibleClient hiện tại. Không thêm model hoặc dependency parser/graph mới.

---

## 1. Phạm vi và quyết định thiết kế

Đây là kế hoạch triển khai, chưa thay đổi mã chạy hoặc prompt. Không tích hợp context_tool/Joern trong lần chuyển schema này; hiện pipeline chỉ truyền source code. Cụm “provided context” trong prompt chỉ cho phép context thực sự được cấp, không cho phép suy diễn contract từ tên hàm.

Không thay policy binary aggregation, retry budget hoặc cấu hình model trong cùng migration. Hai test từng fail về abstention và token multiplier phải được chạy baseline lại và báo riêng; không sửa/xóa test chỉ để migration trông xanh.

### Contract công khai

| Agent | Collection | ID |
|---|---|---|
| Operation | `operations` | `o1`, `o2`, ... |
| State | `states` | `s1`, `s2`, ... |
| Value | `values` | `v1`, `v2`, ... |
| Execution | `executions` | `e1`, `e2`, ... |

Mỗi record có chính xác năm field, không thêm `ref`, `grounding`, `unresolved`, `role`, `effect` vào raw record:

```json
{
  "id": "e1",
  "location": "L4",
  "entities": ["i", "n"],
  "claim": "reaching L4 requires i < n",
  "evidence": "L2: if (i >= n) return;"
}
```

- `location`: chuẩn hóa thành `L<number>` duy nhất, tương đối với `sample.code`, đánh số từ 1. Đây là điểm claim có hiệu lực/được thiết lập, không bắt buộc là dòng evidence.
- `entities`: danh sách tên/biểu thức entity từ source; bỏ trùng, không rỗng ở từng phần tử. Cho phép `[]` cho execution claim thuần control flow không có entity đặt tên. Khuyến khích root và quantity liên quan; không suy diễn alias từ tên gần giống.
- `claim`: phát biểu ngắn, có scope rõ; không verdict, CWE hoặc safety obligation.
- `evidence`: vẫn là string. Một đoạn code trực tiếp có thể để nguyên; với bằng chứng nhiều dòng dùng từng dòng `L2: <exact substring>\nL3: <exact substring>`. Không ghép đoạn không liên tiếp thành một substring giả.
- Collection rỗng hợp lệ. Không bắt LLM tạo record chỉ vì regex tìm được cú pháp; empty output được thống kê như coverage signal, không tự chứng minh an toàn.
- Budget giữ các trần hiện tại: Operation 12, State 16, Value 20, Execution 20. Không dùng số lượng tối thiểu.

### Ranh giới suy luận

- Operation mô tả hành động; Value mô tả quan hệ đại lượng kết quả. Chỉ giữ cả hai khi chúng đóng góp thông tin khác nhau.
- Execution sở hữu điều kiện để đến một vị trí và short-circuit/order. Value chỉ lặp lại điều kiện đó nếu kết hợp thêm facts để tạo constraint mới có ích.
- State nói trạng thái ở một điểm cụ thể, không biến một phép kiểm tra thành kết luận non-NULL vô điều kiện.
- Không khẳng định dominance hoặc constraint xuyên qua vùng `...` bị lược bỏ nếu source được cung cấp không đủ chứng minh.
- Grounding xác nhận evidence xuất hiện trong source, không chứng minh claim suy ra đúng. Stage 3 vẫn phải đối chiếu claim với evidence và scope.

### Metadata và references

Raw model giữ nguyên năm field. Grounding lưu trong `output.grounding_by_ref`, ví dụ key `execution_agent.executions[0]`, chứa claim_line, evidence matches và trạng thái. Payload consumer dùng wrapper:

```json
{
  "ref": "execution_agent.executions[0]",
  "agent_key": "execution_agent",
  "fact": {
    "id": "e1", "location": "L4", "entities": ["i", "n"],
    "claim": "reaching L4 requires i < n",
    "evidence": "L2: if (i >= n) return;"
  }
}
```

Refs phải khớp collection của agent, index zero-based và tồn tại. Không giữ fallback tự sửa index vượt mảng theo kiểu one-based. Không dùng ID trần làm evidence_refs của output mới; operation_id vẫn là `o1`.

## 2. File map

| File | Trách nhiệm |
|---|---|
| `src/agents/SemanticContract.py` (mới) | Collection map, schema version, parse location, validate record, enumerate/resolve refs |
| `src/agents/SemanticLinker.py` (mới) | Linker v2, ranking và tạo clusters; tách phần đang cần thay khỏi Pipeline.py |
| `src/agents/ArtifactContract.py` (mới) | Fingerprint và kiểm tra compatibility/dependency của stage artifacts |
| `src/agents/prompts/SemanticAgent/{Operation,State,Value,Execution}_Agent.yml` | Common rules và schema mới cho từng agent |
| `src/agents/QualityGate.py` | Grounding claim/evidence, empty-output policy cho v2 |
| `src/agents/Pipeline.py` | Orchestration, prompt payload, stage reads/writes và diagnostics |
| `src/agents/BaseAgent.py` | Chỉ sửa nếu cần plumbing validation; giữ flow API/retry hiện tại |
| `src/agents/prompts/Obligation_Reasoner.yml` | Consumer claims và refs mới |
| `src/agents/prompts/Obligation_Adjudicator.yml` | Consumer claims, scope và evidence mới |
| `src/UI/cli.py` | Count các collection mới, thông báo stale artifact, output root |
| `tests/test_semantic_contract.py` | Contract/refs/location |
| `tests/test_semantic_grounding.py` | Evidence nhiều dòng và vị trí claim |
| `tests/test_semantic_linker.py` | Link relevance, deterministic order, empty cases |
| `tests/test_claim_consumers.py` | Stage 2/3 payload và refs validation |
| `tests/test_artifact_contract.py` | Stale cache, fingerprint, dependency chain |
| `tests/test_semantic_pipeline_v2.py` | Pipeline dùng scripted client, không gọi API |
| `docs/semantic-claims-v2.md` | Contract, migration và cách chạy đánh giá |

## 3. Thứ tự triển khai và kiểm chứng

### Task 1 — Baseline và fixture nhỏ

- [ ] Kiểm tra AGENTS.md áp dụng, git diff và trạng thái workspace lúc triển khai; giữ các thay đổi của người dùng.
- [ ] Chạy `python -B -m unittest discover -s tests -v`; ghi tên và nguyên nhân từng lỗi baseline. `-B` tránh cập nhật pycache đang được Git theo dõi.
- [ ] Ghi token/verdict artifacts hiện có để so sánh; không coi artifact cũ là baseline mới chạy cùng config.
- [ ] Tạo fixture C nhỏ trong test để kiểm tra schema và dataflow qua pipeline:

```python
CODE = "int f(int *p, int i, int n) {\n  if (i >= n) return 0;\n  if (i < 0) return 0;\n  return p[i];\n}"
OP = {"id": "o1", "location": "L4", "entities": ["p", "i"],
      "claim": "read element p[i]", "evidence": "L4: return p[i];"}
EXEC = {"id": "e1", "location": "L4", "entities": ["i", "n"],
        "claim": "reaching L4 requires 0 <= i < n",
        "evidence": "L2: if (i >= n) return 0;\nL3: if (i < 0) return 0;"}
```

Fixture này không được dùng để khẳng định p non-NULL hoặc buffer dài n; code không cung cấp hai dữ kiện đó.

### Task 2 — Contract dùng chung

- [ ] Viết test contract trước, chạy `python -B -m unittest discover -s tests -p test_semantic_contract.py -v` để xác nhận chưa có implementation.
- [ ] Tạo SemanticContract.py với giao diện:

```python
SCHEMA_VERSION = "semantic-claims-v2"
COLLECTIONS = {"operation_agent": "operations", "state_agent": "states",
               "value_agent": "values", "execution_agent": "executions"}
PREFIXES = {"operation_agent": "o", "state_agent": "s",
            "value_agent": "v", "execution_agent": "e"}
# parse_location(value: str, max_line: int) -> int
# validate_claim_output(output: dict, agent_key: str, max_line: int) -> list[str]
# iter_claims(semantic_model: dict) -> iterable of {ref, agent_key, fact}
# resolve_claim_ref(semantic_model: dict, ref: str) -> dict
```

- [ ] Validate đúng field set, string không rỗng, entities là list string, duplicate ID, prefix đúng agent, location trong source và đúng collection duy nhất. Empty collection pass; `L0`, `L4-L6`, field `role`, collection `records` fail.
- [ ] Resolve refs strict: `state_agent.states[0]` hợp lệ; `state_agent.values[0]`, index âm/vượt mảng, `s1` dùng làm ref đều fail.
- [ ] Chạy lại nhóm test; review API này trước khi đổi consumers.

Ví dụ assertion cần có:

```python
self.assertEqual(4, parse_location("L4", 5))
self.assertEqual([], validate_claim_output({"states": []}, "state_agent", 5))
self.assertTrue(validate_claim_output({"operations": [dict(OP, role="read")]}, "operation_agent", 5))
```

### Task 3 — Grounding và empty output

- [ ] Test EXEC ở L4 với evidence L2/L3 phải pass grounding; raw record sau validate vẫn đúng năm field.
- [ ] Test một trong hai evidence fragment không tồn tại phải fail; không chấp nhận chỉ vì fragment còn lại match.
- [ ] Test exact substring không prefix được tìm trong toàn source; nhiều vị trí match phải lưu tất cả/cảnh báo ambiguity, không tự gán vị trí claim thành vị trí evidence.
- [ ] Sửa QualityGate dùng SemanticContract. Thêm `ground_claim_evidence(fact, source_code) -> dict` trả metadata, không mutate fact.
- [ ] Với evidence có prefix, kiểm tra substring ở đúng dòng chỉ định. Với nhiều đoạn, kiểm tra từng đoạn; dấu chấm phẩy bên trong code không dùng làm separator tự động.
- [ ] Thay hard rejection empty-output của v2 bằng diagnostics riêng. Update test cũ về empty operation theo contract mới, giải thích thay đổi có chủ đích; không thay hai test baseline không liên quan.
- [ ] Chạy `python -B -m unittest discover -s tests -p test_semantic_grounding.py -v`.

### Task 4 — Bốn prompt và Stage 1 orchestration

- [ ] Viết lại bốn YAML theo common rules trong attachment; cùng năm field, collection và prefix theo bảng.
- [ ] Giữ biến `numbered_function_code`, giữ `operation_anchors_json` cho ba agent sau. Anchors mang đầy đủ `location/entities/claim/evidence`.
- [ ] Thống nhất evidence multiline có line prefix, scope L-number và quy tắc không suy diễn qua omitted gaps.
- [ ] Operation chỉ mô tả action có ý nghĩa; State bỏ assignment đại lượng; Value ưu tiên quan hệ/constraint tổng hợp; Execution ưu tiên điều kiện reachability.
- [ ] Giữ record cap hiện tại như giới hạn tối đa. Thêm ví dụ empty output hợp lệ và unknown callee không được suy luận allocate/free/copy từ tên.
- [ ] Sửa `operation_anchors_for_llm`, `add_anchor_line_windows` đọc location qua parse_location; giữ line numbers gốc của sample.
- [ ] Lưu grounding_by_ref ngoài raw records; summarize_grounding đọc metadata mới.
- [ ] Load tất cả prompt bằng SimpleYaml và render bằng PromptAgent với fixture; kiểm tra không còn placeholder thiếu, schema collection đúng. Kiểm tra bằng loader thật, không chỉ yaml.safe_load.

### Task 5 — Linker v2 deterministic

Không parse prose claim thành alias/dominance hoặc cố dựng lại role/effect cũ. Chỉ dùng cấu trúc entities/location để tạo candidate associations; confidence mô tả độ liên quan, không phải bằng chứng safety.

- [ ] Viết test `o1`/`e1` cùng L4, có shared entity `i`: phải link. Fact về `value` gần L4 nhưng không shared entity: không link.
- [ ] Test missing entities ở cả hai phía không tạo link; đây chặn lại lỗi so sánh field thiếu bằng nhau trong linker cũ.
- [ ] Test execution thuần control flow entities=[] chỉ link khi cùng claim location với operation; nhãn location_only và confidence weak.
- [ ] Implement `build_context_links_record(sample_id, semantic_model)` trong SemanticLinker.py, dùng iter_claims. Một cluster cho mỗi operation, kể cả không có support facts.
- [ ] Quy tắc initial ranking: shared entity +5; cùng location +3; khoảng cách 1..10 +1. Chỉ link nếu có shared entity và khoảng cách <=80, hoặc cùng location với execution không entity. Không gọi quan hệ này là reaches/dominates/state-valid.
- [ ] Strong khi có shared entity và cùng location; các candidate khác weak. Không truyền alias qua chuỗi, không strip field/index để tạo false identity.
- [ ] Tie-break theo score giảm, distance tăng, ref tăng. Giữ tối đa 16 support facts/cluster; payload Stage 2 giữ tối đa 4, ưu tiên một fact mỗi family trước khi fill bằng rank. Ghi đầy đủ omitted counts.
- [ ] Payload cluster giữ id/operation_id/anchor_ref/link_confidence/anchor_operation/linked_facts. Anchor và linked facts dùng wrapper đã định nghĩa; bỏ field role/effect/base_entity cũ khỏi input v2.
- [ ] Test chạy hai lần cho JSON tương đương; test giới hạn/cân bằng family, unlinked operations và omitted counts.
- [ ] Chạy `python -B -m unittest discover -s tests -p test_semantic_linker.py -v`.

### Task 6 — Stage 2 consumer và refs

- [ ] Sửa compact_context_links_for_llm/compact_fact_for_llm bảo toàn cả năm field bên trong wrapper. Claim không được mất trong whitelist.
- [ ] Đổi prompt Reasoner giải thích claim là semantic assertion có source evidence, link chỉ là candidate association. Không biến claim của extractor thành established API contract.
- [ ] Giữ output obligations: id, cluster_id, operation_id, coverage_category, safety_requirement, applicable_condition, link_confidence, evidence_refs, note.
- [ ] Cập nhật ví dụ refs sang `state_agent.states[0]`, `value_agent.values[0]`, `execution_agent.executions[0]`.
- [ ] Validate operation_id tồn tại và đúng anchor của cluster; cluster_id tồn tại; anchor_ref bắt buộc trong evidence_refs; mọi cited ref phải nằm trong payload thực sự gửi Stage 2. Copy link_confidence phải đúng cluster.
- [ ] Bỏ permissive correction one-based refs của đường v2; lỗi dẫn đến validation retry hiện tại.
- [ ] Test wrapper giữ claim/entities/location, ref cũ bị reject, cluster-operation mismatch bị reject, ref tồn tại trong Stage 1 nhưng đã bị compact bỏ vẫn bị reject.
- [ ] Chạy `python -B -m unittest discover -s tests -p test_claim_consumers.py -v`.

### Task 7 — Stage 3 consumer

- [ ] Filter evidence bằng strict refs, giữ wrapper đủ năm field và anchor. Không truncate thêm khiến mất ref Stage 2 đã trích; đã có cap ở Stage 2.
- [ ] Nếu payload tham chiếu record không tồn tại, dừng với validation error thay vì trả whole semantic model fallback.
- [ ] Prompt adjudicator nhận nghĩa của location (claim relevance), evidence prefix (source support), claim (derived assertion). Nếu claim không được evidence hỗ trợ hoặc scope không đủ, áp dụng policy violation=0 hiện tại.
- [ ] Giữ output adjudications với obligation_id/violation/refs; kiểm tra đúng một kết quả cho mỗi obligation và mọi refs thuộc evidence được cấp cho chính obligation đó.
- [ ] Test fake batch có ref ngoài obligation, duplicate/missing ID bị reject; valid batch giữ verdict aggregation như trước.
- [ ] Chạy lại test_claim_consumers.py; không thay aggregation để giải quyết test abstention trong task này.

### Task 8 — Artifact isolation và cache invalidation

- [ ] Bổ sung output root tùy chọn cho VulSORPipeline và CLI `--output-root`; v2 mặc định dùng `stages/semantic-v2/<sample_id>/...`. Cập nhật scripts/eval_cwe_coverage.py nhận `--stage-root` để đánh giá đúng thư mục.
- [ ] Không sửa/convert artifact v1 thành claim bằng suy đoán. Chạy v2 cần tạo lại Stage 1, 1.5, 2, 3.
- [ ] Tạo ArtifactContract.py cung cấp `fingerprint(payload)` bằng SHA256 của canonical JSON và `validate_artifact(record, expected_metadata)`.
- [ ] Metadata stage gồm schema_version, source hash, split/dataset identity, prompt/config fingerprint, pipeline revision và upstream hashes. Stage 1.5 ghi linker version và hash Stage 1; Stage 2 ghi hash 1.5; Stage 3 ghi hash Stage 1 và Stage 2.
- [ ] `run_sample` chỉ reuse stage khi metadata và dependencies match. Khi Stage 1 đổi, rebuild 1.5 và invalidate 2/3. `run_exact_stage` từ chối dependency stale và nêu stage cần rerun.
- [ ] Dry-run có namespace/fingerprint khác real run; không cho stub dry-run tái dùng như kết quả API.
- [ ] Giữ LLM cache key theo prompt/payload hiện tại; prompt mới tự đổi key. Không xóa cache cũ hoặc kết quả v1.
- [ ] Test thay source/prompt/linker/upstream hash khiến reuse bị từ chối; test v1 thiếu metadata; test chạy stage 2 riêng trên stale 1.5 báo rõ lỗi.
- [ ] Chạy `python -B -m unittest discover -s tests -p test_artifact_contract.py -v`.

### Task 9 — Diagnostics, CLI và integration

- [ ] Audit toàn bộ loop collection `operations/records`: summaries, grounding summary, input quality, evidence status, conflict diagnostics, preview, token reporting; chuyển sang COLLECTIONS hoặc iter_claims.
- [ ] Dùng `rg -n 'records|base_entity|target_line|unresolved|operation_agent.operations|stage_root' src tests scripts` để kiểm tra các consumer còn sót; phân biệt literal v1 trong test compatibility với đường runtime v2.
- [ ] Viết scripted client có cùng interface chat_completion, lần lượt trả bốn semantic outputs mới, một reasoner output và một adjudicator output. Không gọi mạng hoặc dùng API key.
- [ ] Trong TemporaryDirectory, kiểm tra run_sample đi hết 3 stage, tạo 1.5, token usage cộng đúng, ref giữ nguyên, claim tới tận Stage 3 và raw records vẫn đúng năm field.
- [ ] Thêm ca tất cả collections rỗng, evidence không hợp lệ, multi-line evidence, stale previous run; xác nhận không crash do collection rename.
- [ ] Chạy `python -B -m unittest discover -s tests -p test_semantic_pipeline_v2.py -v`, rồi toàn bộ suite. Chỉ chấp nhận baseline failures đã được đối chiếu; không có lỗi mới.

### Task 10 — Đánh giá thực nghiệm và bàn giao

- [ ] Ghi docs/semantic-claims-v2.md về contract và vị trí output mới; nêu rõ việc grounding không chứng minh derivation.
- [ ] Chọn cùng danh sách sample cố định cho v1/v2: mẫu dài test_000000, các mẫu ngắn, benign/vulnerable và paired counterparts nếu metadata có. Không dùng labels/CWE để viết prompt riêng cho từng sample.
- [ ] Trước hết review offline payload trên fixtures và sample code thật; không lấy output mẫu cũ để giả lập hiệu quả của prompt mới.
- [ ] Nếu được phép gọi API, chạy v2 vào output root riêng; chạy lại baseline v1 với cùng model/config khi cần so sánh công bằng. Không overwrite artifact cũ.
- [ ] Thống kê input/output/total token theo agent và stage, retry count, cache hits, fact counts, grounding failures, weak/unlinked clusters, omitted facts, obligation coverage và verdict.
- [ ] Báo precision/recall/F1 chỉ trên cohort đủ và có ground truth; với cohort nhỏ báo TP/FP/TN/FN và hạn chế. Không cam kết schema ngắn hơn sẽ giảm token hay tăng accuracy trước phép đo.
- [ ] Bàn giao diff, kết quả tests, vị trí artifacts, baseline failures còn tồn tại và các giới hạn của linker. Commit theo nhóm coherent khi workflow triển khai cho phép; chỉ stage file thuộc migration, không stage pycache hoặc dữ liệu ngoài scope.

## 4. Điều kiện hoàn tất

- [ ] Bốn prompt và mọi consumer dùng đúng schema v2, không cần field v1 để chạy.
- [ ] location L4 với supporting evidence L2/L3 được validate đúng.
- [ ] Empty collections hợp lệ, API/parse errors vẫn được phân biệt với empty semantic output.
- [ ] Ref tồn tại, đúng collection, đúng payload và đúng obligation; không silent index repair.
- [ ] Linker deterministic; không link do None == None hoặc chỉ vì gần dòng đối với fact có entity không liên quan.
- [ ] Stage 2/3 nhận đầy đủ claim, entities, location, evidence.
- [ ] Artifact v1/dry-run/stale không bị reuse thành real v2 result.
- [ ] Integration tests không gọi API pass; suite không có regression ngoài baseline đã ghi.
- [ ] Báo cáo kết quả phân biệt structural correctness đã kiểm thử với chất lượng semantic cần đánh giá thực nghiệm.

## 5. Review kế hoạch

Đã đối chiếu common rules với collection map, ID, five-field contract, empty-output policy, role boundaries và multi-statement evidence. Stage 1.5 không yêu cầu các structured fields đã bị bỏ, và không tạo lại chúng bằng cách parse claim. Các thay đổi Stage 2/3 tập trung ở payload/ref validation; policy verdict giữ riêng để phép đánh giá migration có thể diễn giải được.
