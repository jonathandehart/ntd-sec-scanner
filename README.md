```markdown
# AI-Assisted C/C++ Static Vulnerability Scanner

A compiler-based static analysis tool built with **Clang/LLVM LibTooling** and **Python** that detects memory-safety vulnerabilities in C/C++ Abstract Syntax Trees (ASTs), extracts full enclosing function contexts, and pipes findings to an LLM for false-positive triage and automated remediation.

## Architecture

```text
[C/C++ Source] ──▶ [Clang LibTooling AST Scanner] ──▶ [Structured JSON] ──▶ [Python LLM Triage] ──▶ [Verdict + Patch]
```

1. **AST Static Analysis (`scanner.cpp`):** Uses Clang's `ASTMatchers` to traverse C/C++ syntax trees rather than brittle regex matching.
2. **Context Extraction:** Climbs the AST (`hasAncestor`) to locate the enclosing `FunctionDecl` and slices the exact source text via `clang::Lexer`, serializing findings with `llvm::json`.
3. **AI Triage & Patching (`triage.py`):** Evaluates surrounding buffer sizes and integer bounds via local Ollama or OpenAI-compatible APIs to separate true vulnerabilities from safe false positives and generate memory-safe C++ fixes.

## Supported Security Rules

| Rule ID | Vulnerability Class | Description |
| :--- | :--- | :--- |
| **`CWE-120-UNSAFE-STRING`** | Unbounded Buffer Copy | Detects calls to unsafe C string functions (`strcpy`, `strcat`, `sprintf`, `gets`). |
| **`CWE-190-MALLOC-OVERFLOW`** | Integer Overflow in Heap Allocation | Variant-analysis rule detecting arithmetic multiplication inside `malloc`/`realloc` arguments (`malloc(count * sizeof(T))`). |

## Prerequisites & Build (macOS)

Requires Homebrew LLVM and CMake:

```bash
brew install llvm cmake
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```

## Usage

### 1. Run the C++ AST Scanner Alone (JSON Output)
```bash
./build/sec-scanner vulnerable_test.cpp --
```

### 2. Run the Full AI Triage Pipeline
Supports local [Ollama](https://ollama.com) (`llama3.2` by default) or OpenAI (`export OPENAI_API_KEY=...`):

```bash
./build/sec-scanner vulnerable_test.cpp -- | python3 triage.py
```

### Sample Output
```text
Loaded 3 static analysis finding(s). Running AI triage...

=== Finding #1: CWE-120-UNSAFE-STRING in process_packet() ===
- Verdict: TRUE POSITIVE
- Reasoning: `network_input` has an unknown length and can overflow the fixed 32-byte `buffer` via `strcpy`.
- Suggested Fix: Replace `strcpy(buffer, network_input);` with `snprintf(buffer, sizeof(buffer), "%s", network_input);`.

=== Finding #2: CWE-120-UNSAFE-STRING in init_tag() ===
- Verdict: FALSE POSITIVE
- Reasoning: The source string `"NTD"` is a 4-byte compile-time constant that safely fits inside the 8-byte `tag` buffer.
- Suggested Fix: None required.
```
```
