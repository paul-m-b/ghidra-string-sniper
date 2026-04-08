#!/usr/bin/env python3
"""Drive CodeQL to collect incoming and outgoing references for one source function.

This is the source-side half of a broader matching pipeline. The script:

1. Creates or reuses a CodeQL database for a source tree.
2. Resolves a single target function by name, with optional filters.
3. Runs focused incoming and outgoing reference queries for that function.
4. Emits a comparison-friendly JSON artifact for downstream binary matching.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
QUERY_DIR = SCRIPT_DIR / "queries"
GENERATED_QUERY_DIR = SCRIPT_DIR / ".generated_queries"
QLPACK_FILE = SCRIPT_DIR / "qlpack.yml"


@dataclass(frozen=True)
class FunctionIdentity:
    name: str
    qualified_name: str
    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    @property
    def stable_id(self) -> str:
        return f"{self.file}:{self.start_line}:{self.start_column}:{self.qualified_name}"


@dataclass(frozen=True)
class CallEdge:
    direction: str
    source: FunctionIdentity
    target: FunctionIdentity
    callsite_file: str
    callsite_start_line: int
    callsite_start_column: int
    callsite_end_line: int
    callsite_end_column: int


class CodeQLRunnerError(RuntimeError):
    """Raised when the CodeQL workflow cannot complete successfully."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect incoming and outgoing function references for a source-side "
            "target function using the CodeQL CLI."
        )
    )
    parser.add_argument("--config", type=Path, help="Optional JSON config file.")
    parser.add_argument(
        "--codeql-cli",
        default=None,
        help="Path to the CodeQL CLI binary. Defaults to $CODEQL_CLI or 'codeql'.",
    )
    parser.add_argument("--database", type=Path, default=None, help="CodeQL database path.")
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="Source tree root used to build or create the database.",
    )
    parser.add_argument(
        "--language",
        default=None,
        help="CodeQL language identifier. Default: c-cpp",
    )
    parser.add_argument(
        "--build-command",
        default=None,
        help="Build command used when creating a compiled-language CodeQL database.",
    )
    parser.add_argument(
        "--rebuild-database",
        action="store_true",
        help="Delete and recreate the database before querying.",
    )
    parser.add_argument("--target-name", default=None, help="Unqualified target function name.")
    parser.add_argument(
        "--target-file-substring",
        default=None,
        help="Substring used to disambiguate the target function's source file.",
    )
    parser.add_argument(
        "--target-qualified-name-substring",
        default=None,
        help="Substring used to disambiguate the target function's qualified name.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to write the JSON output. Default: ./codeql_target_refs.json",
    )
    parser.add_argument(
        "--keep-generated-queries",
        action="store_true",
        help="Keep rendered queries in the output directory for debugging.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print CodeQL commands before executing them.",
    )
    return parser.parse_args()


def load_config(config_path: Path | None) -> dict[str, Any]:
    if config_path is None:
        return {}
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def choose_value(cli_value: Any, config: dict[str, Any], *keys: str, default: Any = None) -> Any:
    if cli_value not in (None, False):
        return cli_value
    cursor: Any = config
    for key in keys:
        if not isinstance(cursor, dict) or key not in cursor:
            return default
        cursor = cursor[key]
    return cursor


def build_settings(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(args.config)
    settings = {
        "codeql_cli": choose_value(args.codeql_cli, config, "codeql_cli", default=os.environ.get("CODEQL_CLI", "codeql")),
        "database": Path(choose_value(args.database, config, "database", default=SCRIPT_DIR / "codeql-db")),
        "source_root": choose_value(args.source_root, config, "source_root"),
        "language": choose_value(args.language, config, "language", default="c-cpp"),
        "build_command": choose_value(args.build_command, config, "build_command"),
        "rebuild_database": bool(args.rebuild_database or choose_value(None, config, "rebuild_database", default=False)),
        "target_name": choose_value(args.target_name, config, "target", "name"),
        "target_file_substring": choose_value(args.target_file_substring, config, "target", "file_substring"),
        "target_qname_substring": choose_value(
            args.target_qualified_name_substring,
            config,
            "target",
            "qualified_name_substring",
        ),
        "output": Path(choose_value(args.output, config, "output", default=SCRIPT_DIR / "codeql_target_refs.json")),
        "keep_generated_queries": bool(
            args.keep_generated_queries or choose_value(None, config, "keep_generated_queries", default=False)
        ),
        "verbose": bool(args.verbose or choose_value(None, config, "verbose", default=False)),
    }

    if not settings["target_name"]:
        raise CodeQLRunnerError("A target function name is required. Use --target-name or provide target.name in config.")
    return settings


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def ensure_pack_file() -> None:
    if not QLPACK_FILE.exists():
        raise CodeQLRunnerError(f"Missing CodeQL pack file: {QLPACK_FILE}")


def generated_query_dir(keep_generated_queries: bool) -> Path:
    GENERATED_QUERY_DIR.mkdir(parents=True, exist_ok=True)
    if not keep_generated_queries:
        for query_file in GENERATED_QUERY_DIR.glob("*.ql"):
            query_file.unlink()
    return GENERATED_QUERY_DIR


def render_query(template_name: str, replacements: dict[str, str], output_path: Path) -> Path:
    template_path = QUERY_DIR / template_name
    content = template_path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        content = content.replace(key, value)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def ql_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def run_command(command: list[str], verbose: bool) -> subprocess.CompletedProcess[str]:
    if verbose:
        print("[codeql-runner]", " ".join(command))
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        raise CodeQLRunnerError(
            f"Command failed with exit code {completed.returncode}: {' '.join(command)}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return completed


def create_or_reuse_database(settings: dict[str, Any]) -> None:
    database = settings["database"]
    if database.exists() and not settings["rebuild_database"]:
        return

    if database.exists() and settings["rebuild_database"]:
        shutil.rmtree(database)

    source_root = settings["source_root"]
    if source_root is None:
        raise CodeQLRunnerError(
            "Database creation requires --source-root (or source_root in config) when the database does not already exist."
        )

    command = [
        str(settings["codeql_cli"]),
        "database",
        "create",
        str(database),
        f"--language={settings['language']}",
        f"--source-root={source_root}",
        "--overwrite",
    ]
    if settings["build_command"]:
        command.append(f"--command={settings['build_command']}")

    run_command(command, settings["verbose"])


def decode_bqrs_to_rows(
    codeql_cli: str,
    bqrs_path: Path,
    expected_width: int,
    verbose: bool,
) -> list[list[str]]:
    csv_path = bqrs_path.with_suffix(".csv")
    run_command(
        [
            codeql_cli,
            "bqrs",
            "decode",
            "--format=csv",
            f"--output={csv_path}",
            str(bqrs_path),
        ],
        verbose,
    )

    rows: list[list[str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if row:
                rows.append(row)

    if rows and len(rows[0]) != expected_width and len(rows[0]) == expected_width + 1:
        rows = [row[1:] for row in rows]

    if rows and _looks_like_header(rows[0], expected_width):
        rows = rows[1:]

    return rows


def _looks_like_header(row: list[str], expected_width: int) -> bool:
    if len(row) != expected_width:
        return False

    normalized = [cell.strip().lower() for cell in row]
    if all(cell == f"col{index}" for index, cell in enumerate(normalized)):
        return True

    return "name" in normalized[0] or "direction" in normalized[0]


def run_query(
    settings: dict[str, Any],
    query_path: Path,
    expected_width: int,
    suffix: str,
) -> list[list[str]]:
    bqrs_path = settings["output"].with_suffix(f".{suffix}.bqrs")
    ensure_parent_dir(bqrs_path)
    run_command(
        [
            str(settings["codeql_cli"]),
            "query",
            "run",
            f"--database={settings['database']}",
            f"--output={bqrs_path}",
            str(query_path),
        ],
        settings["verbose"],
    )
    return decode_bqrs_to_rows(str(settings["codeql_cli"]), bqrs_path, expected_width, settings["verbose"])


def parse_function_identity(row: list[str], offset: int) -> FunctionIdentity:
    return FunctionIdentity(
        name=row[offset + 0],
        qualified_name=row[offset + 1],
        file=row[offset + 2],
        start_line=int(row[offset + 3]),
        start_column=int(row[offset + 4]),
        end_line=int(row[offset + 5]),
        end_column=int(row[offset + 6]),
    )


def resolve_target(settings: dict[str, Any], rendered_query_dir: Path) -> FunctionIdentity:
    candidate_query = render_query(
        "target_candidates.ql.tmpl",
        {"__TARGET_NAME__": ql_string(settings["target_name"])},
        rendered_query_dir / "target_candidates.ql",
    )
    rows = run_query(settings, candidate_query, expected_width=7, suffix="target_candidates")
    candidates = [parse_function_identity(row, 0) for row in rows]

    filtered = filter_candidates(
        candidates,
        file_substring=settings["target_file_substring"],
        qname_substring=settings["target_qname_substring"],
    )

    if not filtered:
        raise CodeQLRunnerError(
            "No source function matched the requested target.\n"
            f"Target name: {settings['target_name']}\n"
            f"File filter: {settings['target_file_substring']}\n"
            f"Qualified name filter: {settings['target_qname_substring']}"
        )

    if len(filtered) > 1:
        summary = "\n".join(f"  - {candidate.stable_id}" for candidate in filtered[:20])
        raise CodeQLRunnerError(
            "Target resolution is ambiguous. Provide a tighter file or qualified-name filter.\n"
            f"Candidates:\n{summary}"
        )

    return filtered[0]


def filter_candidates(
    candidates: Iterable[FunctionIdentity],
    file_substring: str | None,
    qname_substring: str | None,
) -> list[FunctionIdentity]:
    filtered = list(candidates)
    if file_substring:
        filtered = [candidate for candidate in filtered if file_substring in candidate.file]
    if qname_substring:
        filtered = [candidate for candidate in filtered if qname_substring in candidate.qualified_name]
    return filtered


def collect_edges(
    settings: dict[str, Any],
    target: FunctionIdentity,
    rendered_query_dir: Path,
    template_name: str,
    suffix: str,
    direction: str,
) -> list[CallEdge]:
    query = render_query(
        template_name,
        {
            "__TARGET_FILE__": ql_string(target.file),
            "__TARGET_START_LINE__": str(target.start_line),
            "__TARGET_START_COLUMN__": str(target.start_column),
        },
        rendered_query_dir / template_name.replace(".tmpl", ""),
    )
    rows = run_query(settings, query, expected_width=19, suffix=suffix)

    edges: list[CallEdge] = []
    for row in rows:
        if direction == "incoming":
            resolved_target = parse_function_identity(row, 0)
            other = parse_function_identity(row, 7)
            source = other
            sink = resolved_target
        else:
            source = parse_function_identity(row, 0)
            other = parse_function_identity(row, 7)
            sink = other

        edges.append(
            CallEdge(
                direction=direction,
                source=source,
                target=sink,
                callsite_file=row[14],
                callsite_start_line=int(row[15]),
                callsite_start_column=int(row[16]),
                callsite_end_line=int(row[17]),
                callsite_end_column=int(row[18]),
            )
        )
    return edges


def build_output(
    settings: dict[str, Any],
    target: FunctionIdentity,
    incoming_edges: list[CallEdge],
    outgoing_edges: list[CallEdge],
) -> dict[str, Any]:
    incoming_neighbors = sorted({edge.source.qualified_name or edge.source.name for edge in incoming_edges})
    outgoing_neighbors = sorted({edge.target.qualified_name or edge.target.name for edge in outgoing_edges})

    return {
        "metadata": {
            "codeql_cli": str(settings["codeql_cli"]),
            "database": str(settings["database"]),
            "source_root": str(settings["source_root"]) if settings["source_root"] else None,
            "language": settings["language"],
            "query_pack": str(QLPACK_FILE),
        },
        "target": asdict(target),
        "incoming_edges": [serialize_edge(edge) for edge in incoming_edges],
        "outgoing_edges": [serialize_edge(edge) for edge in outgoing_edges],
        "comparison_ready": {
            "incoming_neighbor_ids": incoming_neighbors,
            "outgoing_neighbor_ids": outgoing_neighbors,
            "incoming_count": len(incoming_edges),
            "outgoing_count": len(outgoing_edges),
        },
    }


def serialize_edge(edge: CallEdge) -> dict[str, Any]:
    return {
        "direction": edge.direction,
        "source": asdict(edge.source),
        "target": asdict(edge.target),
        "callsite": {
            "file": edge.callsite_file,
            "start_line": edge.callsite_start_line,
            "start_column": edge.callsite_start_column,
            "end_line": edge.callsite_end_line,
            "end_column": edge.callsite_end_column,
        },
    }


def main() -> int:
    try:
        ensure_pack_file()
        settings = build_settings(parse_args())
        ensure_parent_dir(settings["output"])
        create_or_reuse_database(settings)
        rendered_query_dir = generated_query_dir(settings["keep_generated_queries"])

        target = resolve_target(settings, rendered_query_dir)
        incoming_edges = collect_edges(
            settings,
            target,
            rendered_query_dir,
            template_name="incoming_refs.ql.tmpl",
            suffix="incoming_refs",
            direction="incoming",
        )
        outgoing_edges = collect_edges(
            settings,
            target,
            rendered_query_dir,
            template_name="outgoing_refs.ql.tmpl",
            suffix="outgoing_refs",
            direction="outgoing",
        )

        result = build_output(settings, target, incoming_edges, outgoing_edges)
        settings["output"].write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote CodeQL reference graph to {settings['output']}")
        return 0
    except CodeQLRunnerError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

