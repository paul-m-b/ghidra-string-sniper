# Ghidra String Sniper: UI <-> Backend Connection

This document outlines the implemented UI/backend connection and the new cross-platform
pipeline contract.

## What Changed

- Added a single Python entrypoint for the full pipeline:
  - `ghidra_string_sniper_ext/data/python/extension_interface/run_pipeline.py`
- Standardized output paths across the Python backend using a shared helper:
  - `ghidra_string_sniper_ext/data/python/gss_paths.py`
- Made the Python backend cross-platform by removing Windows/WSL temp-path logic and
  using explicit output directories passed in from the Java side.
- Wired the UI action to run the pipeline and then load results.
- Enabled Program tracking in the plugin so the UI can resolve the current binary.

## How It Works Now (End-to-End)

1. **User clicks** the "Search For Strings" toolbar action.
2. **UI prompts** for the OpenRouter API key and writes it to a temp file.
3. **UI resolves** the active program's executable path (or prompts for a binary if missing).
4. **UI launches** the Python pipeline as a background task.
5. **Python pipeline**:
   - Extracts and prioritizes strings.
   - Queries Sourcegraph.
   - Performs function matching.
6. **UI reads** `results.json` and `MATCHES.json` from the pipeline output directory
   and populates the table.

## Pipeline Contract

The Java side **always** supplies explicit paths. The Python side **never** infers OS
temp folders or project-relative paths.

### Entry Script

`ghidra_string_sniper_ext/data/python/extension_interface/run_pipeline.py`

### Arguments

- `--binary <ABS_PATH>`: binary/executable path
- `--out <ABS_DIR>`: output directory for all artifacts
- `--token <ABS_PATH>`: path to a file containing the OpenRouter API key
- `--language <LANG_ID>`: optional Ghidra language id
- `--model <MODEL>`: optional LLM model override
- `--max-strings <N>`: optional cap on string count

### Outputs (all under `--out`)

- `results.json`
- `MATCHES.json`
- `GSS_Results/<hash>/...` (Sourcegraph results)
- `GSS_decomps/<hash>/decomp.txt`

## UI Integration Details

### Program Tracking

`StringSniperPlugin` now sets/clears the current program on activation/deactivation.

### Search Action

`SearchForStringsAction` now:

- Resolves `Program.getExecutablePath()` (or prompts for a file).
- Creates a temp output directory for this run.
- Calls `PythonRunner.runSystemPython(...)` with the pipeline entry script.
- Loads results from `outputDir/results.json` and `outputDir/MATCHES.json`.
- Updates the table and sorts by score.

## Cross-Platform Notes

- The backend no longer depends on Windows temp APIs or `/mnt/c` paths.
- Paths are passed in from Java and resolved with standard `Path` operations.
- The runner uses `python` on Windows and `python3` on Unix-like platforms.
- `pyghidra` is required. The UI runs a preflight check and shows an error if it is not installed.
- `PYGHIDRA_PROJECT_DIR` is set to the pipeline output directory to satisfy absolute path requirements.

## Files Touched / Added

- `ghidra_string_sniper_ext/src/main/java/ghidra_string_sniper/SearchForStringsAction.java`
- `ghidra_string_sniper_ext/src/main/java/ghidra_string_sniper/StringSniperPlugin.java`
- `ghidra_string_sniper_ext/src/main/java/ghidra_string_sniper/StringSniperComponentProvider.java`
- `ghidra_string_sniper_ext/data/python/llm_interact.py`
- `ghidra_string_sniper_ext/data/python/string_prioritize.py`
- `ghidra_string_sniper_ext/data/python/sourcegraph_query.py`
- `ghidra_string_sniper_ext/data/python/function_match.py`
- `ghidra_string_sniper_ext/data/python/feature_extract.py`
- `ghidra_string_sniper_ext/data/python/extension_interface/get_strings.py`
- `ghidra_string_sniper_ext/data/python/extension_interface/analyze_strings.py`
- `ghidra_string_sniper_ext/data/python/extension_interface/run_pipeline.py` (new)
- `ghidra_string_sniper_ext/data/python/gss_paths.py` (new)

## Usage Summary

1. Load a program in Ghidra.
2. Click the "Search For Strings" action.
3. Provide an API key.
4. Wait for the pipeline to finish.
5. Browse ranked strings and open the Results tab for details.
