# CodeQL Testing

This folder contains the source-side CodeQL prototype for resolving a target
function and extracting its incoming and outgoing call references. The output is
normalized into JSON so it can be compared later against the binary-side call
graph recovered from Ghidra.

## Files

- `codeql_runner.py`: Python driver that creates or reuses a CodeQL database,
  runs the queries, and writes a comparison-friendly JSON artifact.
- `queries/target_candidates.ql.tmpl`: Resolves candidate functions by name.
- `queries/incoming_refs.ql.tmpl`: Collects caller-to-target references.
- `queries/outgoing_refs.ql.tmpl`: Collects target-to-callee references.
- `example_config.json`: Example configuration for the driver.

## What The Driver Produces

The runner writes JSON with:

- A resolved `target` function identity.
- `incoming_edges` with caller information and exact callsite locations.
- `outgoing_edges` with callee information and exact callsite locations.
- A `comparison_ready` block that provides stable neighbor lists and counts for
  downstream source-vs-binary matching.

## Usage

If you already have a CodeQL database:

```bash
python3 research/CODEQL_TESTING/codeql_runner.py \
  --database /path/to/codeql-db \
  --target-name target_function_name \
  --target-file-substring src/target_file.cpp \
  --output research/CODEQL_TESTING/codeql_target_refs.json
```

If you want the script to create the database first:

```bash
python3 research/CODEQL_TESTING/codeql_runner.py \
  --source-root /path/to/source/tree \
  --database research/CODEQL_TESTING/codeql-db \
  --build-command "cmake --build build" \
  --target-name target_function_name \
  --target-file-substring src/target_file.cpp
```

Or use the JSON config:

```bash
python3 research/CODEQL_TESTING/codeql_runner.py \
  --config research/CODEQL_TESTING/example_config.json
```

## Notes

- The prototype currently targets CodeQL's `c-cpp` extractor and direct
  `FunctionCall` relationships.
- The driver resolves ambiguity before running the focused caller and callee
  queries, which makes the output much easier to compare against binary
  function-reference graphs later.
- For compiled languages, database creation is usually only reliable when
  `--build-command` matches the project's real build.
