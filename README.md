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

## Offline File Context

Context repo được xây dựng trước khi chạy pipeline. Mỗi record PrimeVul được
tra `func_hash` trong `file_info.json` để lấy file nguồn và span của target;
chỉ file đó được đưa vào Joern. Extractor tạo các nhóm quan hệ cần cho LLM:
data-flow, control dependencies, declarations/types/contracts và call
relations, sau đó chọn lọc, loại trùng và giới hạn toàn bộ context ở 2.000
token. Context vượt ngân sách bị đánh dấu `oversized` và không ghi record dở.

Luồng chạy:

```text
primevul_test_pairs.jsonl + file_info.json
  -> resolve func_hash -> source file + line span
  -> Joern parse một file -> extract source-level relations
  -> sparse selection -> validate 2,000-token budget
  -> JSONL output
```

Chạy thử:

```powershell
python scripts/context_tool.py build `
  --config config\primevul.yaml `
  --pairs data\primevul\primevul_test_pairs.jsonl `
  --file-info data\primevul\file_info.json `
  --dataset-root data\primevul `
  --output data\primevul\primevul_withcontext.jsonl `
  --limit 2 `
  --progress
```

Java 21, `joern` và `joern-parse` phải có trên `PATH`. File output là artifact
offline; pipeline chính chỉ đọc context đã tạo, không clone repository và
không tạo CPG lúc runtime.

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
