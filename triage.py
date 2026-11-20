#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

def query_llm(prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        url = "https://googleapis.com"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        payload = {
            "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
    else:
        # Defaults to local Ollama
        url = os.environ.get("OLLAMA_URL", "http://localhost:11434/v1/chat/completions")
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": os.environ.get("OLLAMA_MODEL", "llama3.2"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }

    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

def main():
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        print("No input received from scanner.")
        return

    findings = json.loads(raw_input)
    if not findings:
        print("No static analysis warnings found.")
        return

    print(f"Loaded {len(findings)} static analysis finding(s). Running AI triage...\n")

    for idx, item in enumerate(findings, 1):
        prompt = f"""You are a senior platform security engineer reviewing C/C++ static analysis alerts.
Analyze the finding below and respond concisely in this exact format:
- Verdict: [TRUE POSITIVE or FALSE POSITIVE]
- Reasoning: [1-2 sentences explaining buffer bounds or integer overflow risk]
- Suggested Fix: [Brief C/C++ code snippet fixing the issue, or "None required"]

Rule Triggered: {item['rule_id']}
Function: {item['enclosing_function']} ({item['file']}:{item['line']})
Source Code:
```cpp
{item['function_code']}
```"""

        print(f"=== Finding {idx}: {item['rule_id']} in {item['enclosing_function']}() ===")
        try:
            verdict = query_llm(prompt)
            print(verdict)
        except Exception as e:
            print(f"[Error contacting LLM]: {e}")
            print("Tip: Start Ollama locally (`ollama serve`) or export OPENAI_API_KEY.")
        print()

if __name__ == "__main__":
    main()
