# Ghidra String Sniper: UI <-> Backend Connection

This document describes the current Option B pipeline: Java handles all program-dependent
work; Python handles LLM + internet work.

## How It Works (End-to-End)

1. **User clicks** the "Search For Strings" toolbar action.
2. **Java exports strings** from the open program into `strings_raw.json`.
3. **Python ranks strings** (heuristics + LLM) using `rank_strings.py`, writing `results.json`.
4. **Java decompiles** referenced functions for the ranked strings and writes `GSS_decomps/<hash>/decomp.txt`.
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
  pipeline.log
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
- It first checks the current run's `outputDir/GSS_Results/<hash>`.
- If not found, it scans `<project>/gss_runs/*/GSS_Results/<hash>`.

## Logging

- A per-run log file is written to `pipeline.log` inside the run output directory.
- Java logs are written to the Ghidra Log window and to the Console (via `ConsoleService` when available).
- Python logs stream into the same `pipeline.log` and the Ghidra Console.

## Scoring semantics

- **Open Source Confidence**: LLM usefulness score from `results.json` (0-10).
- **Match Confidence**: LLM similarity score from `MATCHES.json` (0-10) based on decompiled function vs Sourcegraph match.
