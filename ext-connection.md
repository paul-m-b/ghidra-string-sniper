# Ghidra String Sniper: UI <-> Backend Connection

This document describes the current Option B pipeline: Java handles all program‑dependent
work; Python handles LLM + internet work.

## How It Works (End‑to‑End)

1. **User clicks** the "Search For Strings" toolbar action.
2. **Java exports strings** from the open program into `strings_raw.json`.
3. **Python ranks strings** (heuristics + LLM) using `rank_strings.py`, writing `results.json`.
4. **Java decompiles** referenced functions for the top strings and writes `GSS_decomps/<hash>/decomp.txt`.
5. **Python analyzes** Sourcegraph + function match via `analyze_strings.py`, writing `GSS_Results/*` and `MATCHES.json`.
6. **UI loads** `results.json` + `MATCHES.json` and populates the Strings table.

## Output Layout (per run)

All artifacts are stored per binary inside the Ghidra project directory:

```
<project>/gss_runs/<binaryName>_<hash>/
  strings_raw.json
  results.json
  MATCHES.json
  GSS_Results/<hash>/*
  GSS_decomps/<hash>/decomp.txt
```

Only the most recent run is kept (the folder is deleted and recreated each run).

The API token is stored once at:

```
<project>/gss_token.txt
```

## Python Entry Scripts

### `rank_strings.py`

Arguments:
- `--strings <ABS_PATH>`: path to `strings_raw.json`
- `--out <ABS_DIR>`: output directory (GSS_OUT)
- `--token <ABS_PATH|VALUE>`: OpenRouter token (file path or raw string)
- `--model <MODEL>` (optional)
- `--max-strings <N>` (optional)

Outputs:
- `results.json`

### `analyze_strings.py`

Arguments:
- `--out <ABS_DIR>`: output directory (GSS_OUT)
- `--token <ABS_PATH|VALUE>`: OpenRouter token

Outputs:
- `GSS_Results/<hash>/*`
- `MATCHES.json`

## Java Responsibilities

- Export strings from `Program` (value + address) to `strings_raw.json`.
- Read `results.json` and decompile functions for those strings only.
- Write `GSS_decomps/<hash>/decomp.txt`.
- Launch Python for LLM + Sourcegraph steps.
- Populate UI from `results.json` + `MATCHES.json`.

## View Source File

- The Results tab uses the string hash to look up matching Sourcegraph files.
- It first checks the current run’s `outputDir/GSS_Results/<hash>`.
- If not found, it scans `<project>/gss_runs/*/GSS_Results/<hash>`.

## TODOs

### Core pipeline correctness
- Ensure all backend outputs live under the run output dir (`GSS_OUT`) and no code reads/writes `./`.
- Add a “decomp present?” flag in results to distinguish string‑only vs function‑matchable entries.
- Treat “no references” as a first‑class state (log once, mark string as non‑matchable).

### UI clarity + behavior
- Rename columns to reflect what they display (LLM confidence vs function match score).
- Show a status badge in Results: `No decomp`, `Sourcegraph hit`, `Function match`.
- On pipeline failure, keep strings/results empty and show a single detailed error dialog.

### Output handling / diagnostics
- Persist a `pipeline.log` in the run output dir for troubleshooting.
- Surface the run output dir in UI (e.g., “Open Output Folder” action).

### Sourcegraph & matching robustness
- Skip function-match step for hashes with empty `decomp.txt`.
- Add retry/backoff for Sourcegraph calls and rate limit detection.

### Token handling
- Validate token before running (simple LLM check or OpenRouter status call).
- Clear warning if token missing/invalid.

### Performance
- Limit decomp + Sourcegraph to top‑N prioritized strings (configurable).
- Use smaller decomp timeouts and skip repeated failures.

### Configuration
- Add a settings dialog for model, max strings, entropy range, Sourcegraph on/off, output retention.

### UX polish
- Replace placeholder link with actual Sourcegraph URL.
- Add “Copy string/hash” context actions.
- Add a small help panel explaining the pipeline and scores.
