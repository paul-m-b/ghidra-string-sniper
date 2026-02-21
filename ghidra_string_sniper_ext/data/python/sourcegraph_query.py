import requests
import hashlib
import json
import time
import sys
import os
from collections import defaultdict


class SOURCEGRAPH_QUERY:
    def __init__(self):
        self.repo_stats = defaultdict(lambda: {
            "match_count": 0,
            "matched_files": []   # list of {file, lines, query_hash}
        })


    """
    Queries sourcegraph for public repositories containing strings in specified input file, creates folder named GSS_results
    containing the returned file contents from sourcegraph with a small header containing the line number of the matches.
    Also calls get_readme if 4th argument is true.
    """
    def get_repos(self, query: str, match_count: str, query_hash: str) -> set():
        """
        with open(input_file_name, 'r') as file:
            search_terms = []
            for line in file:
                stripped_line = line.strip()
                if stripped_line:  # Only include non-empty lines
                    # Escape any quotes in the search term
                    escaped_term = stripped_line.replace('"', '\\"')
                    search_terms.append(f'{escaped_term}')

                if operator.lower() == "and":
                    query = " AND ".join(search_terms)
                elif operator.lower() == "or":
                    query = " OR ".join(search_terms)
                else:
                    query = " ".join(search_terms)
        """

        query_filtered = (
            f'type:file lang:c++ lang:c count:{match_count} '
            f'content:{json.dumps(query)}'
        )

        #determines a repository we think is being used in the binary
        #if there are more than X matches with confidence >= Y we are "interested" in it
        #download any repositories we are "interested" in.
        #think of and find a good way to store this repository

        #Implementation:
        #Find a way to create a list of unique repos and a counter value for each time it's been referenced like in line 131
        #Let's say any repo with >=4 matches with confidence 8.0 are labeled as interesting
        #Download the repositories into the current pathway, creating a subfolder called "Interesting repos" and subfolders for each repo labeled as interesting
        #Is there a way to store this repository inside the folder? Won't it get too big with some repos?

        url: str = "https://sourcegraph.com/.api/graphql"
        
        payload: dict = {
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
            "variables": {
                "query": query_filtered
            }
        }

        print(f"\nSearching for {query[:100]}")
        
        try:
            response: requests.Response = requests.post(url, json=payload, timeout=30)
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
                    print (f"{match['repository']['name']} in file {match['file']['name']}")
                    repo_full = match['repository']['name']
                    repos.add(repo_full)

                    # List of line numbers with matches
                    matched_lines = list({line_match['lineNumber'] for line_match in match['lineMatches']})


                    repo_name_only: str = repo_full.split('/')[-1]
                    matched_file: str = match['file']['name'].split('.')[0]
                    file_name: str = repo_name_only + '_' + matched_file + '.txt'
                    '''
                    folder_name: str = query.encode("utf-8")
                    md5_hash = hashlib.md5()
                    md5_hash.update(folder_name)
                    folder_name: str = str(md5_hash.hexdigest())
                    '''
                    folder_name = query_hash

                    match_msg: str = ""
                    for num in matched_lines:
                        match_msg += str(num+6) + " "

                    os.makedirs(f"GSS_results/{folder_name}/", exist_ok=True)

                    with open(f"GSS_results/{folder_name}/"+file_name, 'w') as file:
                        file.write("-----------GSS-----------\n" + 
                                  "query: " + query + "\n" + 
                                  match_msg + "\n-------------------------\n\n" + 
                                  match['file']['content'])

                    self.repo_stats[repo_full]["match_count"] += 1
                    self.repo_stats[repo_full]["matched_files"].append({
                        "file": match["file"]["name"],
                        "lines": matched_lines,
                        "query_hash": query_hash
                    })
            print(f"\nSourcegraph found {result_count} matches from {len(repos)} repo(s):")
            return repos
            
        except Exception as e:
            print(f"Error: {e}")
            return set()


    def iterate_search_strings(self):
        with open("./results.json") as file:
            useful_strings = json.load(file)

        for string in useful_strings.keys():
            self.get_repos(string, 5, useful_strings[string]["hash"])
        
        # After all queries are done, persist repo summary for repo downloading
        self.save_repo_match_summary()

    def save_repo_match_summary(self, out_path="GSS_results/repo_match_summary.json"):
        os.makedirs("GSS_results", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.repo_stats, f, indent=2)

        print(f"\nSaved repo match summary to {out_path}")

"""
Queries sourcegraph for the readmes of given repository url. Stores the content of the readme in GSS_results in a text file.
"""
def get_readme(repo_url: str):
    url: str = "https://sourcegraph.com/.api/graphql"

    repo_user: str = repo_url.split('/')[-2]
    repo_name: str = repo_url.split('/')[-1]

    query: str = f"repo:^github\.com/{repo_user}/{repo_name}$ file:^README(\.md|\.txt)?$"
    
    graphql_query: str = """
    query SearchReadme($query: String!) {
        search(query: $query, version: V2) {
            results {
                results {
                    __typename
                    ... on FileMatch {
                        file {
                            content
                        }
                    }
                }
            }
        }
    }
    """
    
    payload: dict = {
        "query": graphql_query,
        "variables": {
            "query": query
        }
    }

    try:
        response: requests.Response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        results = data['data']['search']['results']

        for result in results['results']:
            with open("GSS_results/"+repo_name + " _README.txt", 'w') as file:
                file.write(result['file']['content'])
                print (f'Found readme for {repo_url}')

    except Exception as e:
        print(f"Error: {e}")
        return

