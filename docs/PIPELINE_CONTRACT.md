# Pipeline Contract

This document is the current contract between the Java plugin and Python scripts.
If any input/output changes, update this file and implementation together.

## Pipeline phases and ownership

1. **Java: export strings**
   - Input: open `Program`
   - Output: `strings_raw.json`

2. **Python: rank strings (LLM + heuristics)**
   - Script: `extension_interface/rank_strings.py`
   - Input: `strings_raw.json`
   - Output: `results.json`

3. **Java: decompile referenced functions**
   - Input: `results.json` + `Program`
   - Output: `GSS_decomps/<hash>/decomp.txt`

4. **Python: Sourcegraph + function match**
   - Script: `extension_interface/analyze_strings.py`
   - Input: `results.json`, `GSS_decomps/<hash>/decomp.txt`
   - Output: `GSS_Results/<hash>/*`, `MATCHES.json`

5. **Java: interesting repo aggregation + cloning**
   - Input: `results.json`, `MATCHES.json`, `GSS_Results/*`
   - Output: `Interesting_repos/<repo>/...`, `Interesting_repos/interesting_repos.json`

6. **Java: UI population**
   - Input: pipeline outputs above
   - Output: `Strings`, `Results`, `Repos` tabs

## Post-pipeline repo actions

These actions are triggered from the `Repos` tab, not during the main pipeline.

1. **Auto Compile (repo row)**
   - Python script: `extension_interface/agentic_compile.py`
   - Input: cloned repo path (`Interesting_repos/<repo>`)
   - Output: `compiled/<repo>/agentic_compile*.json|.log` and copied binaries

2. **Add to Version Tracking (repo row)**
   - Java action in `StringSniperComponentProvider`
   - Input: selected binary from `compiled/<repo>/...`
   - Output: imported program under project path `/gss_compiled/<destination-program>/...` and a VT session file in the project root

## Output directory layout (`GSS_OUT`)

```
<project>/gss_runs/<binaryName>_<hash>/
  strings_raw.json
  results.json
  MATCHES.json
  GSS_Results/<hash>/*
  GSS_decomps/<hash>/decomp.txt
  Interesting_repos/interesting_repos.json
  Interesting_repos/<repo>/
  compiled/<repo>/
    agentic_compile.log
    agentic_compile_result.json
    agentic_compile_transcript.json
    <copied binaries>
  pipeline.log
```

## JSON schemas

### `strings_raw.json` (Java output)

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

### `results.json` (Python output)

Keys are exact string values from `strings_raw.json`.

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

### `MATCHES.json` (Python output)

Keys are hash values from `results.json`. Values are:
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

### `Interesting_repos/interesting_repos.json` (Java output)

Top-level keys are repo identifiers.

```json
{
  "github.com/AaronKalair/C-Web-Server": {
    "match_count": 9,
    "average_match_score": 8.114,
    "strong_hits": 9,
    "result_confidences": [8, 8, 7, 7],
    "hashes": ["..."],
    "strings": ["..."],
    "repo_url": "https://sourcegraph.com/github.com/AaronKalair/C-Web-Server",
    "clone_url": "https://github.com/AaronKalair/C-Web-Server.git",
    "clone": {
      "status": "cloned",
      "target_dir": ".../Interesting_repos/github.com__AaronKalair__C-Web-Server",
      "clone_url": "https://github.com/AaronKalair/C-Web-Server.git"
    }
  }
}
```

## Invariants

- Strings in `results.json` must be exact values from `strings_raw.json`.
- `MATCHES.json` must exist even when no matches are found.
- `GSS_decomps/<hash>/decomp.txt` may be missing for strings with no resolvable xref decomp.
- Interesting repos are selected by Java thresholds (`match score`, `confidence`, and multi-hit requirements).
- `Auto Compile` and `Add to Version Tracking` require a successful pipeline run that populated the `Repos` tab.

## Token handling

- OpenRouter token is stored at `<project>/gss_token.txt`.
- Java passes token path to Python scripts via `--token`.

## Logging

- Main pipeline logs: `pipeline.log` (Java + Python lines).
- Per-repo compile logs: `compiled/<repo>/agentic_compile.log` and transcript/result JSON.
- VT session creation/correlator results are reflected in Ghidra project objects and UI dialogs.
