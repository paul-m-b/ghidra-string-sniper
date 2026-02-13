import os
from pathlib import Path


def get_output_dir() -> Path:
    out = os.environ.get("GSS_OUT", "")
    if out:
        return Path(out).expanduser().resolve()
    return Path.cwd().resolve()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def results_json_path() -> Path:
    return get_output_dir() / "results.json"


def matches_json_path() -> Path:
    return get_output_dir() / "MATCHES.json"


def decomps_dir() -> Path:
    return ensure_dir(get_output_dir() / "GSS_decomps")


def sourcegraph_dir() -> Path:
    return ensure_dir(get_output_dir() / "GSS_Results")
