import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from gss_paths import get_output_dir, interesting_repos_dir, matches_json_path, results_json_path

CONF_THRESHOLD = 6
MATCH_THRESHOLD = 7.4
MIN_MATCHES = 4


@dataclass
class RepoCandidate:
    repo: str
    repo_url: str | None = None
    clone_url: str | None = None
    count: int = 0
    score_sum: float = 0.0
    result_confidences: list[int] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)

    def add_hit(self, match_hash: str, match_score: float, result_confidence: int) -> None:
        self.count += 1
        self.score_sum += match_score
        self.result_confidences.append(result_confidence)
        self.hashes.append(match_hash)

    @property
    def average_match_score(self) -> float:
        if self.count == 0:
            return 0.0
        return self.score_sum / self.count

    @property
    def strong_hits(self) -> int:
        return sum(1 for confidence in self.result_confidences if confidence >= CONF_THRESHOLD)
def load_matches() -> dict:
    with open(matches_json_path(), "r", encoding="utf-8") as f:
        return json.load(f)


def load_confidences() -> dict[str, int]:
    with open(results_json_path(), "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        entry["hash"]: int(entry["confidence"])
        for entry in data.values()
        if "hash" in entry and "confidence" in entry
    }


def read_match_metadata(match_path: str) -> dict[str, str | None]:
    path = Path(match_path)
    if not path.is_absolute():
        path = get_output_dir() / path

    if not path.exists():
        logging.warning("Skipping missing match file: %s", path)
        return {"path": str(path), "repo": None, "repo_url": None, "clone_url": None}

    repo = None
    repo_url = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for _, line in zip(range(50), f):
            stripped = line.strip()
            if stripped.startswith("repo: "):
                repo = stripped[len("repo: "):].strip()
            elif stripped.startswith("repo_url: "):
                repo_url = stripped[len("repo_url: "):].strip()
            if repo and repo_url:
                break

    clone_url = derive_clone_url(repo, repo_url)
    return {
        "path": str(path),
        "repo": repo,
        "repo_url": repo_url,
        "clone_url": clone_url,
    }


def derive_clone_url(repo: str | None, repo_url: str | None) -> str | None:
    if repo:
        if repo.startswith(("http://", "https://")):
            return repo if repo.endswith(".git") else repo + ".git"
        if "/" in repo:
            return f"https://{repo}.git"

    if repo_url:
        normalized = repo_url.strip()
        if normalized.startswith("/"):
            normalized = "https://sourcegraph.com" + normalized
        match = re.search(r"https?://sourcegraph\.com/([^/?#]+/[^/?#]+/[^/?#]+)", normalized)
        if match:
            return f"https://{match.group(1)}.git"

    return None


def rank_repos(matches: dict, hash_to_confidence: dict[str, int]) -> dict[str, RepoCandidate]:
    ranked: dict[str, RepoCandidate] = {}

    for match_hash, match_info in matches.items():
        if not isinstance(match_info, list) or len(match_info) < 2:
            continue

        match_path = match_info[0]
        match_score = float(match_info[1] or 0.0)
        result_confidence = hash_to_confidence.get(match_hash, 0)

        if not match_path or match_score < MATCH_THRESHOLD or result_confidence < CONF_THRESHOLD:
            continue

        meta = read_match_metadata(match_path)
        repo = meta["repo"]
        if not repo:
            continue

        candidate = ranked.setdefault(
            repo,
            RepoCandidate(
                repo=repo,
                repo_url=meta["repo_url"],
                clone_url=meta["clone_url"],
            ),
        )
        if not candidate.repo_url and meta["repo_url"]:
            candidate.repo_url = meta["repo_url"]
        if not candidate.clone_url and meta["clone_url"]:
            candidate.clone_url = meta["clone_url"]
        candidate.add_hit(match_hash, match_score, result_confidence)

    return {
        repo: candidate
        for repo, candidate in ranked.items()
        if candidate.count >= MIN_MATCHES and candidate.strong_hits >= MIN_MATCHES
    }


def clone_repo(candidate: RepoCandidate) -> dict[str, str]:
    out_dir = interesting_repos_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    target_dir = out_dir / candidate.repo.replace("/", "__")
    if target_dir.exists():
        logging.info("Repository already downloaded: %s", candidate.repo)
        return {
            "status": "already_present",
            "target_dir": str(target_dir),
            "clone_url": candidate.clone_url or "",
        }

    if not candidate.clone_url:
        logging.warning("No clone URL available for %s", candidate.repo)
        return {
            "status": "missing_clone_url",
            "target_dir": str(target_dir),
            "clone_url": "",
        }

    logging.info("Cloning likely repository %s", candidate.repo)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", candidate.clone_url, str(target_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logging.warning("Clone failed for %s: %s", candidate.repo, result.stderr.strip())
        return {
            "status": "clone_failed",
            "target_dir": str(target_dir),
            "clone_url": candidate.clone_url,
            "stderr": result.stderr.strip(),
        }

    return {
        "status": "cloned",
        "target_dir": str(target_dir),
        "clone_url": candidate.clone_url,
    }


def save_summary(candidates: dict[str, RepoCandidate], clone_results: dict[str, dict[str, str]]) -> Path:
    out_dir = interesting_repos_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "interesting_repos.json"

    serializable = {}
    for repo, candidate in candidates.items():
        serializable[repo] = {
            "match_count": candidate.count,
            "average_match_score": round(candidate.average_match_score, 3),
            "strong_hits": candidate.strong_hits,
            "result_confidences": candidate.result_confidences,
            "hashes": candidate.hashes,
            "repo_url": candidate.repo_url,
            "clone_url": candidate.clone_url,
            "clone": clone_results.get(repo, {}),
        }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    return out_path


def grab_repositories() -> dict[str, dict]:
    matches = load_matches()
    hash_to_confidence = load_confidences()
    candidates = rank_repos(matches, hash_to_confidence)

    if not candidates:
        logging.info("No repositories met the download threshold.")
        save_summary({}, {})
        return {}

    clone_results = {}
    for repo, candidate in candidates.items():
        clone_results[repo] = clone_repo(candidate)

    summary_path = save_summary(candidates, clone_results)
    logging.info("Saved interesting repository summary to %s", summary_path)

    return {
        repo: {
            "match_count": candidate.count,
            "average_match_score": candidate.average_match_score,
            "strong_hits": candidate.strong_hits,
            "clone": clone_results.get(repo, {}),
        }
        for repo, candidate in candidates.items()
    }


def main() -> None:
    grab_repositories()


if __name__ == "__main__":
    main()
