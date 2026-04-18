# Ghidra String Sniper

Ghidra String Sniper helps triage stripped binaries by:

1. Ranking extracted strings with heuristics + LLM assistance.
2. Searching Sourcegraph for likely open-source matches.
3. Matching decompiled function context against source results.
4. Surfacing interesting repositories in the UI for follow-on actions.

## Current workflow

Pipeline run (`Search For Strings`) produces:

- `Strings` tab: ranked strings, confidence, entropy, hash, match score.
- `Results` tab: per-string details and source file links.
- `Repos` tab: interesting repositories (derived from strong multi-string hits).

For each repository row in `Repos`:

- `Visit Repo` opens the GitHub URL.
- `Auto Compile` runs the sandboxed agentic compiler and stores artifacts under:
  - `<project>/gss_runs/<binaryId>/compiled/<repo>/...`
- `Add to Version Tracking` imports a selected compiled binary into the project and runs auto VT against the currently open destination program.

## Where outputs live

Filesystem artifacts are written under:

- `<project>/gss_runs/<binaryId>/...`

Important outputs include:

- `strings_raw.json`
- `results.json`
- `MATCHES.json`
- `GSS_Results/...`
- `GSS_decomps/...`
- `Interesting_repos/interesting_repos.json`
- `Interesting_repos/<repo>/...`
- `compiled/<repo>/...`

Version Tracking outputs are stored as Ghidra project domain objects (inside project storage, not plain files):

- Imported compiled programs under project folder path `/gss_compiled/<destination-program>/...`
- VT sessions created in the project root folder.

## Documentation

See [docs/README.md](docs/README.md).

## License

MIT License
