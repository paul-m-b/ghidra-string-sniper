import requests
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess

class SOURCEGRAPH_QUERY:
    def __init__(self):
        # Windows temp folder for saving results
        temp_root = self.get_windows_temp_path()
        self.temp_dir = temp_root / "GSS_Results"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.results_json_path = self.temp_dir / "results.json"

        # Project JSON source
        self.project_results_path = Path("./results.json")

        print(f"[INFO] results.json will be saved to: {self.results_json_path}")

    # -------------------------------------------------------------------
    @staticmethod
    def get_windows_temp_path():
        try:
            win_temp = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-Command", "[IO.Path]::GetTempPath()"],
                text=True
            ).strip()
            if win_temp[1] == ":":
                drive = win_temp[0].lower()
                path = win_temp[2:].replace("\\", "/")
                return Path(f"/mnt/{drive}{path}")
            return Path(win_temp)
        except Exception:
            return Path(tempfile.gettempdir())

    # -------------------------------------------------------------------
    def iterate_search_strings(self):
        # ALWAYS read from the project results.json first
        if self.project_results_path.exists():
            with open(self.project_results_path, 'r') as f:
                useful_strings = json.load(f)
        else:
            print("[WARN] No project results.json found.")
            useful_strings = {}

        # Query Sourcegraph for each string
        for string in useful_strings.keys():
            self.get_repos(string, 5, useful_strings[string]["hash"])

        # Save updated results.json to temp folder
        with open(self.results_json_path, 'w') as f:
            json.dump(useful_strings, f, indent=4)

        print(f"[INFO] results.json saved to: {self.results_json_path}")

    # -------------------------------------------------------------------
    def get_repos(self, query: str, match_count: str, query_hash: str) -> set():
        query_filtered = f'type:file lang:c++ lang:c count:{match_count} {query}'
        url = "https://sourcegraph.com/.api/graphql"
        payload = {
            "query": '''
            query Search($query: String!) {
                search(query: $query, version: V2) {
                    results {
                        resultCount
                        results {
                            __typename
                            ... on FileMatch {
                                repository {
                                    name
                                }
                                file {
                                    name
                                    content
                                }
                                lineMatches {
                                    lineNumber
                                }
                            }
                        }
                    }
                }
            }
            ''',
            "variables": {"query": query_filtered}
        }

        print(f"\nSearching for {query[:100]}")

        try:
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            if 'errors' in data:
                print(f"GraphQL Errors: {data['errors']}")
                return set()

            results = data['data']['search']['results']
            result_count = results['resultCount']
            repos = set()

            for match in results['results']:
                if match['__typename'] == 'FileMatch' and match['repository']:
                    print(f"{match['repository']['name']} in file {match['file']['name']}")
                    repos.add(match['repository']['name'])

                    matched_lines = set(lm['lineNumber'] for lm in match['lineMatches'])
                    matched_file = match['file']['name'].split('.')[0]
                    repo_name = match['repository']['name'].split('/')[-1]
                    file_name = f"{repo_name}_{matched_file}.txt"
                    folder_name = query_hash

                    match_msg = " ".join(str(num + 6) for num in matched_lines)

                    os.makedirs(f"GSS_results/{folder_name}/", exist_ok=True)
                    with open(f"GSS_results/{folder_name}/{file_name}", 'w') as f:
                        f.write(
                            "-----------GSS-----------\n"
                            f"query: {query}\n"
                            f"{match_msg}\n"
                            "-------------------------\n\n"
                            f"{match['file']['content']}"
                        )

            print(f"\nSourcegraph found {result_count} matches from {len(repos)} repo(s):")
            return repos

        except Exception as e:
            print(f"Error: {e}")
            return set()
