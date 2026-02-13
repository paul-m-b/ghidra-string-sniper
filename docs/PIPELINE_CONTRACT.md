# Pipeline Contract

This document is the authoritative contract between the Java plugin and the Python backend.
If any of these inputs/outputs change, update this file and the corresponding code.

## Phases and Responsibilities

1. **Java: export strings**
   - Input: open `Program`
   - Output: `strings_raw.json`

2. **Python: rank strings (LLM + heuristics)**
   - Input: `strings_raw.json`
   - Output: `results.json`

3. **Java: decompile referenced functions**
   - Input: `results.json` + `Program`
   - Output: `GSS_decomps/<hash>/decomp.txt`

4. **Python: Sourcegraph + function match**
   - Input: `results.json`, `GSS_decomps/<hash>/decomp.txt`
   - Output: `GSS_Results/<hash>/*`, `MATCHES.json`

5. **Java: UI population**
   - Input: `results.json`, `MATCHES.json`
   - Output: Strings table and Results tab

## Output Directory Layout (GSS_OUT)

```
<project>/gss_runs/<binaryName>_<hash>/
  strings_raw.json
  results.json
  MATCHES.json
  GSS_Results/<hash>/*
  GSS_decomps/<hash>/decomp.txt
  pipeline.log
```

Only the latest run is kept for each binary.

## JSON Schemas

### strings_raw.json (Java output)

```json
{
  "program": "server",
  "language": "x86:LE:64:default",
  "strings": [
    { "value": "HTTP/1.0 200 OK\\n", "address": "00401234" },
    { "value": "Error allocating memory", "address": "00405678" }
  ]
}
```

### results.json (Python output)

Keys are the exact string values from `strings_raw.json`.

```json
{
  "HTTP/1.0 200 OK\\n": {
    "confidence": 8,
    "entropy": 3.42,
    "hash": "52f555f6338c56969edbd52a898b1368"
  },
  "Error allocating memory": {
    "confidence": 7,
    "entropy": 3.01,
    "hash": "6a17df954812b51580e7bdf7e8d6ff3d"
  }
}
```

### MATCHES.json (Python output)

Keys are the hash values from `results.json`. Values are a pair:
`[best_match_file_path, match_score]`.

```json
{
  "52f555f6338c56969edbd52a898b1368": [
    "C:\\Users\\jaden\\...\\GSS_Results\\52f555f6...\\C-Web-Server_server.txt",
    8.0
  ],
  "6a17df954812b51580e7bdf7e8d6ff3d": [
    "",
    0.0
  ]
}
```

## Invariants

- Strings in `results.json` **must** be exact values from `strings_raw.json`.
- Hashing **must** be computed from the canonical string values (no UI normalization).
- All Python output must be written under `GSS_OUT` using `gss_paths.py`.
- `MATCHES.json` must exist even if no matches were found.
- `GSS_decomps/<hash>/decomp.txt` is optional per string; if missing, match score is `0.0`.

## Token Handling

- The OpenRouter token is stored at `<project>/gss_token.txt`.
- Java passes this path to Python via `--token` (Python accepts file path or raw token).

## Logging

- Java and Python append to `pipeline.log` under the run output directory.
- Java logs to the Ghidra Log window and Console.
