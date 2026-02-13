# Architecture Overview

This document explains the mental model behind Ghidra String Sniper. The design is
"Option B": Java owns all program analysis; Python owns LLM + internet work.

## Diagram

```
Ghidra Program
     |
     |  (Java) enumerate strings + addresses
     v
strings_raw.json  ------>  (Python) rank strings  ------>  results.json
     |                                                   |
     |  (Java) xrefs -> functions -> decomp              |
     v                                                   |
GSS_decomps/<hash>/decomp.txt                            |
     |                                                   |
     |  (Python) Sourcegraph + LLM function match        |
     v                                                   v
GSS_Results/<hash>/*  ----------------------------->  MATCHES.json
     |
     |  (Java) load results + matches
     v
UI (Strings + Results)
```

## Components

- **Ghidra UI plugin (Java)**
  - Extracts strings and addresses from the open `Program`.
  - Decompiles functions that reference selected strings.
  - Orchestrates Python phases and loads results into the UI.

- **Python backend**
  - Ranks strings with heuristics + LLM (OpenRouter).
  - Queries Sourcegraph for matching open-source code.
  - Runs LLM-based function matching between decomp and source.

- **External services**
  - **OpenRouter** for LLM calls.
  - **Sourcegraph** for code search.

## Data Flow (button click)

1. Java exports all defined strings + addresses to `strings_raw.json`.
2. Python ranks strings and writes `results.json`.
3. Java decompiles functions that reference the ranked strings, writes `GSS_decomps/...`.
4. Python queries Sourcegraph and writes `GSS_Results/...` and `MATCHES.json`.
5. Java loads `results.json` + `MATCHES.json` and populates the UI.

## Where state lives

Each run writes to a per-binary folder under the Ghidra project directory:

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
The OpenRouter token is stored at `<project>/gss_token.txt`.
