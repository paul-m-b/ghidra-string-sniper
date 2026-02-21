import json
import os
import subprocess
from collections import defaultdict

CONF_THRESHOLD = 8
MIN_MATCHES = 4

REPO_SUMMARY_PATH = "GSS_results/repo_match_summary.json"
CONFIDENCE_PATH = "results.json"
INTERESTING_DIR = "GSS_results/Interesting_repos"


def load_repo_summary():
    with open(REPO_SUMMARY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_confidences():
    with open(CONFIDENCE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # hash -> confidence
    return {
        entry["hash"]: entry["confidence"]
        for entry in data.values()
    }


def rank_repos(repo_summary, hash_to_conf):
    ranked = {}

    for repo, info in repo_summary.items():
        confidences = []
        hashes_seen = set()

        for match in info["matched_files"]:
            h = match["query_hash"]
            if h in hash_to_conf:
                confidences.append(hash_to_conf[h])
                hashes_seen.add(h)

        strong_hits = sum(1 for c in confidences if c >= CONF_THRESHOLD)

        if info["match_count"] >= MIN_MATCHES and strong_hits >= MIN_MATCHES:
            ranked[repo] = {
                "match_count": info["match_count"],
                "confidences": confidences,
                "strong_hits": strong_hits,
                "hashes": list(hashes_seen)
            }

    return ranked


def clone_repo(repo_full_name):
    os.makedirs(INTERESTING_DIR, exist_ok=True)
    target_dir = os.path.join(INTERESTING_DIR, repo_full_name.replace("/", "__"))

    if os.path.exists(target_dir):
        print(f"[=] Already downloaded: {repo_full_name}")
        return

    repo_url = f"https://github.com/{repo_full_name}.git"

    print(f"[+] Cloning {repo_full_name}")
    subprocess.run([
        "git", "clone", "--depth", "1", repo_url, target_dir
    ])


def main():
    repo_summary = load_repo_summary()
    hash_to_conf = load_confidences()

    interesting = rank_repos(repo_summary, hash_to_conf)

    print("\n==== INTERESTING REPOS ====")
    for repo, meta in interesting.items():
        print(f"{repo} | matches={meta['match_count']} | strong_hits={meta['strong_hits']}")

    for repo in interesting:
        clone_repo(repo)

    with open(os.path.join(INTERESTING_DIR, "interesting_repos.json"), "w") as f:
        json.dump(interesting, f, indent=2)

    print(f"\nSaved results to {INTERESTING_DIR}/interesting_repos.json")


if __name__ == "__main__":
    main()