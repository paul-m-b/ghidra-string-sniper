# Ghidra String Sniper: UI <-> Backend Connection

This document outlines the implemented UI/backend connection and the new cross-platform
pipeline contract.

## What Changed

- Added a single Python entrypoint for the full pipeline:
  - `ghidra_string_sniper_ext/data/python/extension_interface/run_pipeline.py`
- Standardized output paths across the Python backend using a shared helper:
  - `ghidra_string_sniper_ext/data/python/gss_paths.py` (in temp)
- Wired the UI action to run the pipeline and then load results.
- Enabled Program tracking in the plugin so the UI can resolve the current binary. (needs to be fixed)

## How It Works

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

### View Source File

- The Results tab uses the string hash to look up matching Sourcegraph files.
- It first checks the current run's `outputDir/GSS_Results/<hash>`.
- If not found, it falls back to the most recent `GSS_Run_*` directory in `%TEMP%`.
- If no files exist for the hash, the UI reports "No file found for this hash."

## Cross-Platform Notes

- The backend no longer depends on Windows temp APIs or `/mnt/c` paths.
- Paths are passed in from Java and resolved with standard `Path` operations.
- The runner uses `python` on Windows and `python3` on Unix-like platforms.
- `pyghidra` is required. The UI runs a preflight check and shows an error if it is not installed.
- `PYGHIDRA_PROJECT_DIR` is set to the pipeline output directory to satisfy absolute path requirements.

## TODOs

- Ensure all backend outputs live under the run output dir (`GSS_OUT`) and no code reads/writes `./`. (Current issues with reading files sometimes)
- Add a “decomp present?” flag in results to distinguish string-only vs function-matchable entries. (Some files are not there)
- Rename columns to reflect what they display (maybe switch from confidence to match score).
- Show a status badge in Results: `No decomp`, `Sourcegraph hit`, `Function match`.
- On pipeline failure, keep strings/results empty and show a single detailed error dialog.
- Persist a `pipeline.log` in the run output dir for troubleshooting.
- Surface the run output dir in UI (e.g., “Open Output Folder” action).
    - Maybe instead of temp have an actualy directory. Cache token too
- Fix blank decomp. Maybe pointer to location in memory inside ghidra
- Better Error logs (token missing, missing directory, ect...)
- Add a settings dialog for model, max strings, entropy range, Sourcegraph on/off, output retention.
- Replace placeholder link with actual Sourcegraph URL.
- Add “Copy string/hash” context actions.
- Add a small help panel explaining the pipeline and scores.
- Fix project lock issue (pyhidra issue)
