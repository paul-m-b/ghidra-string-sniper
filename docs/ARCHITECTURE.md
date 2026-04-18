# Architecture Overview

This document describes the current runtime model of Ghidra String Sniper.

## Design summary

The system is split by responsibility:

- Java orchestrates Ghidra-side analysis, interesting-repo selection, cloning, UI population, and VT integration.
- Python handles LLM + internet-facing analysis (ranking strings, Sourcegraph querying, function matching) and the sandboxed agentic compiler.

## End-to-end flow

```
Ghidra Program
     |
     | (Java) export strings + addresses
     v
strings_raw.json
     |
     | (Python) rank strings
     v
results.json
     |
     | (Java) decompile xref functions per ranked string
     v
GSS_decomps/<hash>/decomp.txt
     |
     | (Python) Sourcegraph search + function matching
     v
GSS_Results/<hash>/*  -----> MATCHES.json
     |
     | (Java) aggregate strong multi-string repo hits
     | (Java) clone interesting repos + write summary JSON
     v
Interesting_repos/<repo>/
Interesting_repos/interesting_repos.json
     |
     | (Java) populate UI tabs
     v
UI (Strings + Results + Repos)
```

## Repos tab actions

After the main pipeline finishes, each row in `Repos` supports:

- `Visit Repo`: open the GitHub repo URL.
- `Auto Compile`: call Python `agentic_compile.py` and save outputs under
  `compiled/<repo>/...`.
- `Add to Version Tracking`: choose a compiled binary, import it into the Ghidra project, create a VT session, run auto correlators, and save results.

## Components

- `SearchForStringsAction` (Java)
  - Owns pipeline orchestration and output directory lifecycle.
  - Builds `interesting_repos.json` and clones repositories with `git clone`.
  - Populates `Strings`, `Results`, and `Repos` tabs.

- `StringSniperComponentProvider` (Java)
  - Renders the tabs.
  - Runs repo-row compile and version-tracking actions.

- Python entrypoints
  - `extension_interface/rank_strings.py`
  - `extension_interface/analyze_strings.py`
  - `extension_interface/agentic_compile.py`

## Run output layout

Each run writes to:

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

Token path:

- `<project>/gss_token.txt`

Note on VT artifacts:

- VT and imported compiled programs are Ghidra project domain objects.
- They are visible in the Ghidra Project UI (for example `/gss_compiled/...`), not as plain files inside `gss_runs`.
