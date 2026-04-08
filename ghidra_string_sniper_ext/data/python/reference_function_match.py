import argparse
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

from function_match import FUNCTION_MATCH


logging.basicConfig(level=logging.INFO)


class REFERENCE_FUNCTION_MATCH:
    def __init__(self):
        self.matcher = FUNCTION_MATCH()

    def run(self, codeql_json_path: str, source_root: str, binary_refs_dir: str,
            output_path: str) -> Dict:
        codeql_path = Path(codeql_json_path).resolve()
        source_root_path = Path(source_root).resolve()
        binary_root = Path(binary_refs_dir).resolve()
        output_dir, output_file = self._resolve_output_paths(Path(output_path).resolve())

        with codeql_path.open("r", encoding="utf-8") as f:
            codeql_data = json.load(f)

        output_dir.mkdir(parents=True, exist_ok=True)
        extracted_source_root = output_dir / "source_function_extracts"
        extracted_source_root.mkdir(parents=True, exist_ok=True)

        incoming_source = self._collect_source_functions(
            codeql_data,
            edge_key="incoming_edges",
            function_key="source",
            direction="incoming",
            source_root=source_root_path,
            extracted_root=extracted_source_root,
        )
        outgoing_source = self._collect_source_functions(
            codeql_data,
            edge_key="outgoing_edges",
            function_key="target",
            direction="outgoing",
            source_root=source_root_path,
            extracted_root=extracted_source_root,
        )

        incoming_binary = self._collect_binary_functions(binary_root / "incoming")
        outgoing_binary = self._collect_binary_functions(binary_root / "outgoing")

        result = {
            "metadata": {
                "codeql_json": str(codeql_path),
                "source_root": str(source_root_path),
                "binary_refs_dir": str(binary_root),
            },
            "incoming": self._match_direction(incoming_source, incoming_binary),
            "outgoing": self._match_direction(outgoing_source, outgoing_binary),
        }

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        return result

    def _resolve_output_paths(self, requested_path: Path) -> Tuple[Path, Path]:
        if requested_path.exists() and requested_path.is_dir():
            output_dir = requested_path
            output_file = output_dir / "reference_match_results.json"
            return output_dir, output_file

        if requested_path.suffix.lower() == ".json":
            output_file = requested_path
            output_dir = output_file.parent
            return output_dir, output_file

        output_dir = requested_path
        output_file = output_dir / "reference_match_results.json"
        return output_dir, output_file

    def _collect_source_functions(self, codeql_data: Dict, edge_key: str, function_key: str,
            direction: str, source_root: Path, extracted_root: Path) -> List[Dict]:
        functions: List[Dict] = []
        seen = set()
        edge_list = codeql_data.get(edge_key, [])

        for edge in edge_list:
            function_info = edge.get(function_key, {})
            identity = self._source_identity(function_info)
            if identity in seen:
                continue
            seen.add(identity)

            extracted_path = self._extract_source_function(
                function_info, source_root, extracted_root / direction
            )
            functions.append({
                "identity": identity,
                "name": function_info.get("name", ""),
                "qualified_name": function_info.get("qualified_name", ""),
                "file": function_info.get("file", ""),
                "start_line": function_info.get("start_line", 0),
                "end_line": function_info.get("end_line", 0),
                "path": str(extracted_path) if extracted_path else None,
            })

        return functions

    def _extract_source_function(self, function_info: Dict, source_root: Path,
            extracted_dir: Path) -> Path | None:
        source_file = function_info.get("file", "")
        start_line = int(function_info.get("start_line", 0))
        function_name = function_info.get("name", "unknown")

        resolved_path = None
        if source_file:
            candidate = source_root / source_file
            if candidate.exists():
                resolved_path = candidate

        if resolved_path is None:
            resolved_path = self._find_source_file_by_name(source_root, function_name)

        if resolved_path is None or not resolved_path.exists():
            logging.warning("Could not locate source file for function %s", function_name)
            return None
        
        try:
            lines = resolved_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            logging.warning("Failed reading source file %s: %s", resolved_path, e)
            return None

        if start_line <= 0 or start_line > len(lines):
            logging.warning("Invalid start line for function %s in %s", function_name, resolved_path)
            return None

        extracted_dir.mkdir(parents=True, exist_ok=True)
        function_lines = self._extract_function_body(lines, start_line)
        if not function_lines:
            logging.warning("Failed to recover full body for function %s in %s", function_name, resolved_path)
            return None

        function_text = "\n".join(function_lines) + "\n"
        output_path = extracted_dir / self._build_source_filename(function_info)
        output_path.write_text(function_text, encoding="utf-8")
        return output_path

    def _extract_function_body(self, lines: List[str], start_line: int) -> List[str]:
        start_index = start_line - 1
        if start_index < 0 or start_index >= len(lines):
            return []

        body_start_index = self._find_open_brace_line(lines, start_index)
        if body_start_index is None:
            return [lines[start_index]]

        brace_depth = 0
        in_block_comment = False
        started = False

        for index in range(start_index, len(lines)):
            line = lines[index]
            scan_line, in_block_comment = self._strip_comments_for_brace_scan(line, in_block_comment)

            for char in scan_line:
                if char == "{":
                    brace_depth += 1
                    started = True
                elif char == "}":
                    brace_depth -= 1
                    if started and brace_depth == 0:
                        return lines[start_index:index + 1]

        return lines[start_index:]

    def _find_open_brace_line(self, lines: List[str], start_index: int) -> int | None:
        in_block_comment = False
        for index in range(start_index, len(lines)):
            scan_line, in_block_comment = self._strip_comments_for_brace_scan(lines[index], in_block_comment)
            if "{" in scan_line:
                return index
            if ";" in scan_line:
                return None
        return None

    def _strip_comments_for_brace_scan(self, line: str, in_block_comment: bool) -> Tuple[str, bool]:
        result = []
        i = 0
        in_string = False
        in_char = False

        while i < len(line):
            char = line[i]
            next_char = line[i + 1] if i + 1 < len(line) else ""

            if in_block_comment:
                if char == "*" and next_char == "/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if not in_string and not in_char and char == "/" and next_char == "*":
                in_block_comment = True
                i += 2
                continue

            if not in_string and not in_char and char == "/" and next_char == "/":
                break

            result.append(char)

            if char == '"' and not in_char and not self._is_escaped(line, i):
                in_string = not in_string
            elif char == "'" and not in_string and not self._is_escaped(line, i):
                in_char = not in_char

            i += 1

        return "".join(result), in_block_comment

    def _is_escaped(self, text: str, index: int) -> bool:
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and text[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        return (backslashes % 2) == 1

    def _find_source_file_by_name(self, source_root: Path, function_name: str) -> Path | None:
        if not function_name:
            return None

        candidate_names = [
            f"{function_name}.c",
            f"{function_name}.cc",
            f"{function_name}.cpp",
            f"{function_name}.h",
            f"{function_name}.hpp",
        ]

        for path in source_root.rglob("*"):
            if not path.is_file():
                continue
            if path.name in candidate_names or path.stem == function_name:
                return path
        return None

    def _collect_binary_functions(self, direction_dir: Path) -> List[Dict]:
        functions: List[Dict] = []
        if not direction_dir.exists():
            return functions

        for file_path in sorted(direction_dir.glob("*.c")):
            functions.append({
                "name": file_path.stem,
                "path": str(file_path.resolve()),
            })
        return functions

    def _match_direction(self, source_functions: List[Dict],
            binary_functions: List[Dict]) -> Dict:
        results = {
            "source_count": len(source_functions),
            "binary_count": len(binary_functions),
            "matches": [],
        }

        for source_function in source_functions:
            source_path = source_function.get("path")
            candidate_scores = []
            best_match = None

            if source_path is not None:
                for binary_function in binary_functions:
                    rating = self.matcher.compare_funcs(
                        source_path,
                        binary_function["path"],
                    )
                    candidate_scores.append({
                        "binary_name": binary_function["name"],
                        "binary_path": binary_function["path"],
                        "rating": rating,
                    })

                if candidate_scores:
                    best_match = max(candidate_scores, key=lambda item: item["rating"])

            results["matches"].append({
                "source_identity": source_function["identity"],
                "source_name": source_function["name"],
                "source_qualified_name": source_function["qualified_name"],
                "source_file": source_function["file"],
                "source_extracted_path": source_path,
                "best_match": best_match,
                "candidate_scores": candidate_scores,
            })

        return results

    def _source_identity(self, function_info: Dict) -> str:
        return "::".join([
            function_info.get("file", ""),
            str(function_info.get("start_line", 0)),
            str(function_info.get("start_column", 0)),
            function_info.get("qualified_name", "") or function_info.get("name", ""),
        ])

    def _build_source_filename(self, function_info: Dict) -> str:
        name = function_info.get("name", "unknown")
        start_line = function_info.get("start_line", 0)
        return f"{self._sanitize(name)}_{start_line}.c"

    def _sanitize(self, value: str) -> str:
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in value) or "unknown"


def main():
    here = Path(__file__).resolve().parent
    os.chdir(here)

    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql-json", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--binary-refs-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    matcher = REFERENCE_FUNCTION_MATCH()
    matcher.run(
        codeql_json_path=args.codeql_json,
        source_root=args.source_root,
        binary_refs_dir=args.binary_refs_dir,
        output_path=args.out,
    )


if __name__ == "__main__":
    main()
