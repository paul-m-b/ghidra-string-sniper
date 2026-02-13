# Sourcegraph Search Behavior

This document describes how query strings are formatted before being sent to Sourcegraph.
The goal is to match C/C++ source code literals as reliably as possible.

## Why formatting is required

Strings in `results.json` are loaded by Python with **real control characters**:
JSON `\\n` becomes an actual newline. If sent raw, Sourcegraph splits the query
into multiple terms and the exact string literal is lost.

## Query workflow

1. **Trim trailing whitespace**
   - `rstrip()` is applied to reduce accidental mismatches.

2. **Convert control chars to C-style escapes**
   - `\r` -> `\\r`
   - `\n` -> `\\n`
   - `\t` -> `\\t`

3. **Quote and escape with `json.dumps`**
   - Produces a safe `content:"..."` filter with properly escaped quotes and backslashes.

4. **Force keyword mode and limit languages**
   - Ensures literal matching and avoids regex interpretation.

5. **CRLF fallback**
   - If the cooked string contains `\n` but not `\r`, a second query is added with
     `\n` replaced by `\r\n` using `OR`.

## Example query

```
type:file patterntype:keyword count:5 (lang:c OR lang:c++)
content:"HTTP/1.0 400 Bad Request\\nServer: CS241Serv v0.1\\nContent-Type: text/html\\n\\n"
```

## Implementation location

- `ghidra_string_sniper_ext/data/python/sourcegraph_query.py`
  - `stringify_for_c_source()`
  - `to_sourcegraph_content_filter()`
  - `build_sg_query()`
