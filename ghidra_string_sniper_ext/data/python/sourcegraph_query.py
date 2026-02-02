import json

import requests

from gss_paths import results_json_path, sourcegraph_dir


class SOURCEGRAPH_QUERY:
    def __init__(self):
        self.temp_dir = sourcegraph_dir()
        self.results_json_path = results_json_path()
        self.project_results_path = self.results_json_path
        print(f"[INFO] results.json will be saved to: {self.results_json_path}")

    # -------------------------------------------------------------------
    def iterate_search_strings(self):
        """Read project results.json and query Sourcegraph for each string."""
        if self.project_results_path.exists():
            with open(self.project_results_path, 'r', encoding='utf-8') as f:
                useful_strings = json.load(f)
        else:
            print("[WARN] No project results.json found.")
            useful_strings = {}

        # Query Sourcegraph for each string
        for string in useful_strings.keys():
            self.get_repos(string, 5, useful_strings[string]["hash"])

        # Save updated results.json to temp folder
        with open(self.results_json_path, 'w', encoding='utf-8') as f:
            json.dump(useful_strings, f, indent=4)

        print(f"[INFO] results.json saved to: {self.results_json_path}")

    # -------------------------------------------------------------------
    def get_repos(self, query: str, match_count: str, query_hash: str) -> set:
        """Query Sourcegraph GraphQL API for matches and save files to temp folder."""
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

            # Save files in same temp folder as results.json
            base_output_dir = self.temp_dir / query_hash
            base_output_dir.mkdir(parents=True, exist_ok=True)

            for match in results['results']:
                if match['__typename'] == 'FileMatch' and match['repository']:
                    repo = match['repository']['name']
                    file = match['file']['name']

                    print(f"{repo} in file {file}")
                    repos.add(repo)

                    matched_lines = set(lm['lineNumber'] for lm in match['lineMatches'])
                    matched_file = file.split('.')[0]
                    repo_name = repo.split('/')[-1]
                    file_name = f"{repo_name}_{matched_file}.txt"

                    match_msg = " ".join(str(num + 6) for num in matched_lines)

                    output_path = base_output_dir / file_name

                    with open(output_path, 'w', encoding='utf-8', errors='replace') as f:
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
