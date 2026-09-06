# VulSOR

VulSOR là framework thử nghiệm cho phát hiện lỗ hổng C/C++ theo hướng
semantic obligations. Project hiện tập trung vào hai phần đầu:

- **B1 Program Analysis**: trích xuất program facts từ source hoặc dataset.
- **B2 Semantic Reconstruction**: dựng các semantic view từ B1, gồm State,
  Value, Execution, Operation. B2 có thể chạy local deterministic hoặc gọi LLM
  để sinh phần diễn giải có kiểm chứng.

Các stage sau như obligation generation, validation, verification,
adjudication và CWE/localization vẫn chưa hoàn thiện. Không nên xem output B1/B2
là verdict vulnerability.

## Yêu Cầu

- Python 3.10+
- Clang có trong `PATH`
- PowerShell hoặc terminal tương đương

Kiểm tra môi trường:

```powershell
python --version
clang --version
```

## Cài Đặt

Từ thư mục project:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Kiểm tra CLI:

```powershell
vulsor --help
vulsor doctor --config configs\primevul.yaml
```

Nếu chưa cài editable package, có thể chạy qua Python module/script tùy môi
trường test hiện tại:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Cấu Hình

Config chính:

```text
configs/primevul.yaml
```

Nội dung chính:

```yaml
tools:
  clang: clang
  clang++: clang++

datasets:
  primevul:
    root: data/PrimeVul_clean
```

Config LLM cho B2:

```text
configs/agent_llm.yaml
```

Mặc định các agent dùng OpenRouter qua biến môi trường:

```powershell
$env:OPENROUTER_API_KEY = "your_api_key"
```

LLM mode không fallback âm thầm. Nếu API lỗi, key sai, timeout, hoặc output sai
schema, command sẽ báo lỗi rõ.

## Chạy Interactive CLI

Chạy không argument để mở menu:

```powershell
vulsor
```

Trong menu:

- `Inspect a sample`: chạy B1.
- `Run semantic agents`: chạy B2.
- `Doctor`: kiểm tra tool.
- `Version`: in version.

Ở mục chọn file source, CLI chỉ gợi ý file C/C++ như `.c`, `.cpp`, `.h`.
Không chọn file config YAML làm source.

## B1 Program Analysis

B1 nhận C/C++ source hoặc sample trong dataset, rồi tạo program facts:

- `functions`
- `operations`
- `definitions`
- `uses`
- `control_flow`
- `cfg_blocks`
- `call_graph`
- `data_flow`
- `links`
- `completeness`
- `missing_context`

Nếu dataset thiếu header/typedef/macro/build flags và Clang không dựng được CFG,
B1 có thể thử một pass recovery bằng synthetic compile context. Mọi stub được
ghi rõ trong `analysis.recovery_assumptions` với `trust:
compile_recovery_only` và `not_evidence_for_verdict: true`; chúng chỉ giúp
khôi phục AST/CFG shape, không được dùng làm bằng chứng vulnerability/CWE.

Chạy B1 cho một sample PrimeVul:

```powershell
vulsor inspect `
  --config configs\primevul.yaml `
  --dataset primevul `
  --split test `
  --sample test_000000 `
  --format json `
  --brain-context-dir brain_context
```

Chạy B1 cho N sample đầu:

```powershell
vulsor inspect `
  --config configs\primevul.yaml `
  --dataset primevul `
  --split test `
  --limit 10 `
  --jobs 1 `
  --format text `
  --brain-context-dir brain_context
```

Chạy B1 cho file C/C++ riêng:

```powershell
vulsor inspect --file path\to\sample.c --format text
```

Output B1 được ghi vào:

```text
brain_context/{dataset}/{split}/{sample_id}.json
brain_context/{dataset}/{split}/manifest.json
```

Ví dụ:

```text
brain_context/primevul/test/test_000000.json
brain_context/primevul/test/manifest.json
```

## B2 Semantic Agents

B2 đọc B1 artifact từ `brain_context`, sau đó tạo bốn semantic view:

- `state_view`
- `value_view`
- `execution_view`
- `operation_view`

Chạy toàn bộ B2 local deterministic cho một sample:

```powershell
vulsor agent `
  --agent all `
  --dataset primevul `
  --split test `
  --sample test_000000 `
  --brain-context-dir brain_context `
  --format text
```

Chạy một agent riêng:

```powershell
vulsor agent `
  --agent operation `
  --dataset primevul `
  --split test `
  --sample test_000000 `
  --brain-context-dir brain_context `
  --format json
```

Chạy lại bỏ cache:

```powershell
vulsor agent `
  --agent all `
  --dataset primevul `
  --split test `
  --sample test_000000 `
  --brain-context-dir brain_context `
  --force
```

`--force` cần khi bạn đã sửa code/prompt/schema và muốn ghi lại artifact thay
vì dùng cache cũ.

Output B2 local nằm ở:

```text
brain_context/{dataset}/{split}/agents/{sample_id}/state.json
brain_context/{dataset}/{split}/agents/{sample_id}/value.json
brain_context/{dataset}/{split}/agents/{sample_id}/execution.json
brain_context/{dataset}/{split}/agents/{sample_id}/operation.json
brain_context/{dataset}/{split}/agents/{sample_id}/agent_semantics.json
brain_context/{dataset}/{split}/agents/{sample_id}/semantic_graph.json
```

Ví dụ:

```text
brain_context/primevul/test/agents/test_000000/agent_semantics.json
brain_context/primevul/test/agents/test_000000/semantic_graph.json
```

Khi merge tạo `agent_semantics.json`, B2 tự sinh thêm `semantic_graph.json` cho
cùng sample. Đây là semantic property graph overlay từ B2, gồm `nodes`,
`edges`, và `summary` để dễ query; nó không phải repository CPG.
Nếu có output LLM hợp lệ trong `experiments/{dataset}/{split}/{agent}/{sample_id}.json`,
merge sẽ nhúng thêm `llm_semantics` vào `agent_semantics.json` và graph sẽ có
node `SemanticObservation`, `ReasoningGroup`, `ReasoningStep` cùng các edge
`SUPPORTED_BY`/`REFERS_TO` về fact hoặc node semantic liên quan.

## B2 Với LLM

Chạy B2 có gọi LLM:

```powershell
$env:OPENROUTER_API_KEY = "your_api_key"

vulsor agent `
  --agent all `
  --dataset primevul `
  --split test `
  --sample test_000000 `
  --brain-context-dir brain_context `
  --llm `
  --llm-config configs\agent_llm.yaml `
  --experiments-dir experiments `
  --force `
  --format text
```

Output local/static vẫn nằm trong `brain_context`. Output LLM nằm trong:

```text
experiments/{dataset}/{split}/{agent}/{sample_id}.json
```

Ví dụ:

```text
experiments/primevul/test/execution/test_000000.json
```

Trong file experiment, phần LLM sinh nằm ở:

```text
llm.result.output.{agent}_view
llm.result.output.reasoning_groups
```

Phần `{agent}_view` ở top-level là view local/static do code sinh, không phải
LLM.

LLM output được giữ gọn:

```json
{
  "operation_view": {
    "observations": [
      {
        "claim": "grounded observation",
        "supporting_fact_ids": ["operation:memcpy:10:3"],
        "confidence": "high",
        "uncertainty": null
      }
    ],
    "summary": "concise summary"
  },
  "reasoning_groups": []
}
```

Không đưa verdict, CWE, CVE hoặc exploitability vào B2.

## Chọn Nhiều Sample Trong Interactive B2

Trong menu `Run semantic agents`, phần chọn sample nhận:

```text
1,3
test_000000,test_000002
1,test_000005
all
```

Khi chọn nhiều sample, CLI sẽ chạy hết các sample trước và tách output bằng
header:

```text
Sample: test_000000 (1/3)
Sample: test_000001 (2/3)
Sample: test_000002 (3/3)
```

Preview output tự động chỉ bật cho một sample để tránh dừng giữa chừng.

## Dataset Layout

PrimeVul raw export và offline repository context được tách rõ:

```text
data/primevul/
  primevul_test_pairs.jsonl
  file_info.json
data/primevul_withcontext/
  test.jsonl
  index.jsonl
  context/
    repos/
    cpg/
    catalog.jsonl
    unavailable.jsonl
```

Raw export không bị sửa. `test.jsonl` chỉ chứa `sample_id` và `code`; `index.jsonl`
chỉ chứa locator repository an toàn cho runtime.

## Luồng B1 -> B2

```text
Dataset/File
  -> B1 inspect
  -> Clang AST/CFG
  -> ProgramFacts + completeness + missing_context
  -> brain_context/{dataset}/{split}/{sample_id}.json
  -> B2 state/value/execution/operation
  -> agent_semantics.json
```

Sơ đồ B1 có sẵn tại:

```text
workspace/b1_program_analysis_flow.svg
```

## Repository Context Theo Revision

Repository context là subsystem độc lập với B1/B2. Mỗi sample chỉ được ánh xạ
đến repository khi có đủ URL, commit SHA 40 ký tự, file, function và source
khớp duy nhất. Metadata thiếu hoặc sai schema được đưa vào rejects; source không
khớp sẽ làm bước prepare thất bại. Hệ thống không tự đoán repository/revision.

Tạo file ánh xạ field, ví dụ `primevul-fields.yaml`:

```yaml
sample_id: id
repository_id: project
repository_url: project_url
revision: commit_id
file_path: file_path
function_name: func_name
code: func
start_line: start_line
end_line: end_line
```

Chuẩn hóa metadata thành repository index không chứa label/CVE/CWE:

Với paired PrimeVul export, dùng Clang AST để tạo compact input/index trước:

```powershell
vulsor repo-context import-primevul `
  --config configs\primevul.yaml `
  --source data\primevul\primevul_test_pairs.jsonl `
  --file-info data\primevul\file_info.json `
  --output-root data\primevul_withcontext
```

Thứ tự offline là `import-primevul` (Clang AST + Git resolve commit cha cho
`target=1`) -> `preprocess --all` (Joern CPG) -> `query` (Joern query-only).
`file_info.json` chỉ định file; span cuối cùng được xác minh từ source ở
revision vulnerable, không lấy từ span của commit vá.

### Context prompt-ready cho một sample

Luồng mới để thử context theo paper không dùng Joern ở runtime. `build-context`
chỉ xử lý đúng một sample trong pha offline: resolve revision, dựng/tái sử dụng
CPG, trích xuất call/data/control/declaration-type, rồi ghi một record JSONL có
bốn section cố định. Sau đó `show-context` chỉ đọc JSONL; không khởi tạo Git,
Joern hoặc CPG.

```powershell
vulsor repo-context build-context --config local-primevul.yaml `
  --dataset primevul --split test --sample test_194963 `
  --output data\primevul_withcontext\context.jsonl

vulsor repo-context show-context --sample test_194963 `
  --input data\primevul_withcontext\context.jsonl
```

Mỗi dòng `context.jsonl` có dạng `sample_id`, `context`, `limitations`.
`context` luôn gồm `[CALL RELATIONS]`, `[DATA DEPENDENCIES]`, `[CONTROL
DEPENDENCIES]`, `[DECLARATIONS AND TYPES]`. Quan hệ không map được phải nằm
trong `limitations`, không được suy diễn thành evidence.

```powershell
vulsor repo-context index `
  --source data\primevul-metadata.jsonl `
  --field-map primevul-fields.yaml `
  --output data\primevul_withcontext\index.jsonl `
  --rejects data\primevul_withcontext\index-rejects.jsonl
```

Kiểm tra tool và chuẩn bị một CPG cho đúng revision:

```powershell
vulsor doctor --config configs\primevul.yaml --repository-context
vulsor repo-context preprocess --config configs\primevul.yaml `
  --dataset primevul --split test --sample test_000000
vulsor repo-context preprocess --config configs\primevul.yaml `
  --dataset primevul --split test --all
vulsor repo-context status --config configs\primevul.yaml `
  --dataset primevul --split test --sample test_000000
```

Một request phải gắn với operation cụ thể và có budget hữu hạn:

```json
{
  "request_id": "req-1",
  "phase": "evaluate",
  "obligation_ref": "obligation-1",
  "repository_ref": {
    "repository_id": "demo",
    "repository_url": "https://example.test/demo.git",
    "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "anchor": {
    "file_path": "src/demo.c",
    "function_name": "target",
    "operation_kind": "call",
    "operation_name": "consume",
    "line": 9,
    "argument_index": 1,
    "entity": "value"
  },
  "questions": ["Giá trị nào được truyền vào consume?"],
  "allowed_relations": ["call", "argument", "data_flow", "control_dependence"],
  "budget": {
    "max_call_depth": 2,
    "max_flow_paths": 10,
    "max_nodes": 150,
    "max_source_lines": 200,
    "max_evidence_items": 30
  }
}
```

Truy vấn và ghi evidence đã ánh xạ về source:

```powershell
vulsor repo-context query --config configs\primevul.yaml `
  --dataset primevul --split test --sample test_000000 `
  --request request.json --output evidence.json
```

`preprocess` is the only offline phase permitted to resolve Git revisions,
build CPGs with `joern-parse`, and smoke-check them. `query` reads only the
catalog, snapshot, and prepared CPG, then runs the Joern query script.
It never fetches, checks out, builds, or smoke-tests. If no READY context is
available, it writes `status: not_found`, `evidence: []`, and limitation
`repository_context_unavailable` (exit code 0).

`data/primevul_withcontext/context/catalog.jsonl` replaces the old catalog
filename `ready.jsonl`; each successful record still has `status: "ready"`.
`unavailable.jsonl` records controlled reasons for samples without usable
repository context. Existing legacy cache directories are neither moved nor
deleted automatically.

Joern 4 requires Java 21. Set `JAVA_HOME`/`JAVACMD` and expose `joern` plus
`joern-parse` on PATH, or use a machine-local config. Do not commit local tool
paths or credentials to shared configuration.

`semantic_graph.json` là semantic overlay cục bộ của B2. `cpg.bin` là Joern
CPG của toàn repository tại một revision xác định. Repository evidence hiện có
CLI và Python service độc lập; chưa tự động nối vào B3/B4 cho đến khi obligation
schema của các stage đó được hoàn thiện.

Joern integration test là opt-in và cần cả `joern` lẫn `joern-parse` trong
`PATH`. Cache lock không bị xóa tự động; nếu process bị dừng đột ngột, cần xác
nhận không còn process sử dụng cache trước khi xử lý lock thủ công.

## Kiểm Tra Và Test

Chạy toàn bộ test:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Compile nhanh các file Python chính sau khi sửa:

```powershell
python -m py_compile src\vulsor\cli.py src\vulsor\agents\BaseAgent.py
```

## Lưu Ý Quan Trọng

- B1/B2 không sinh kết luận vulnerability.
- Dataset label, CWE, CVE, commit metadata không được dùng làm input reasoning.
- `brain_context` là nơi lưu facts/static semantic views.
- `experiments` là nơi lưu kết quả chạy thử, đặc biệt LLM output.
- Nếu dùng LLM mà API lỗi, project phải báo lỗi rõ, không fallback tùy tiện.
- Khi schema/prompt/code thay đổi, dùng `--force` để tránh cache cũ.
