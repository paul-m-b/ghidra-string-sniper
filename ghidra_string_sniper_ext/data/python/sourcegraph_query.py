import json
import os
import time
import requests
from gss_paths import results_json_path, sourcegraph_dir

class SOURCEGRAPH_QUERY:
    def __init__(self):
        pass


    """
    Queries sourcegraph for public repositories containing strings in specified input file, creates folder named GSS_results
    containing the returned file contents from sourcegraph with a small header containing the line number of the matches.
    Also calls get_readme if 4th argument is true.
    """

    def stringify_for_c_source(self, s: str) -> str:
        if s is None:
            return ""
        s = s.rstrip()
        s = s.replace("\r", r"\r").replace("\n", r"\n").replace("\t", r"\t")
        return s

    def to_sourcegraph_content_filter(self, raw: str) -> str:
        cooked = self.stringify_for_c_source(raw)
        return f"content:{json.dumps(cooked)}"

    def build_sg_query(self, raw: str, match_count: int) -> str:
        content = self.to_sourcegraph_content_filter(raw)

        cooked = self.stringify_for_c_source(raw)
        if r"\n" in cooked and r"\r" not in cooked:
            cooked_crlf = cooked.replace(r"\n", r"\r\n")
            content_crlf = f"content:{json.dumps(cooked_crlf)}"
            content = f"({content} OR {content_crlf})"

        return (
            f"type:file patterntype:keyword count:{match_count} "
            f"(lang:c OR lang:c++) "
            f"{content}"
        )

    def get_repos(self, query: str, query_hash: str) -> set():
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
                "query": query
            }
        }

        print(f"\nSearching for {query[:120]}")
        
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
                    repos.add(match['repository']['name'])

                    # List of line numbers with matches
                    matched_lines = set(line_match['lineNumber'] for line_match in match['lineMatches'])

                    matched_file: str = match['file']['name'].split('.')[0]
                    repo_name: str = match['repository']['name'].split('/')[-1]
                    file_name: str = repo_name + '_' + matched_file + '.txt'
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

                    base_dir = sourcegraph_dir() / folder_name
                    base_dir.mkdir(parents=True, exist_ok=True)

                    with open(base_dir / file_name, 'w', encoding='utf-8', errors='replace') as file:
                        file.write("-----------GSS-----------\n" + 
                                  "query: " + query + "\n" + 
                                  match_msg + "\n-------------------------\n\n" + 
                                  match['file']['content'])
            
            print(f"\nSourcegraph found {result_count} matches from {len(repos)} repo(s):")
            return repos
            
        except Exception as e:
            print(f"Error: {e}")
            return set()


    def iterate_search_strings(self):
        with open(results_json_path(), encoding='utf-8', errors='replace') as file:
            useful_strings = json.load(file)

        for string in useful_strings.keys():
            sg_query = self.build_sg_query(string, match_count=5)
            self.get_repos(sg_query, useful_strings[string]["hash"])


"""
Queries sourcegraph for the readmes of given repository url. Stores the content of the readme in GSS_results in a text file.
"""
def get_readme(repo_url: str):
    url: str = "https://sourcegraph.com/.api/graphql"

    repo_user: str = repo_url.split('/')[-2]
    repo_name: str = repo_url.split('/')[-1]

    query: str = rf"repo:^github\.com/{repo_user}/{repo_name}$ file:^README(\.md|\.txt)?$"
    
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
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        results = data['data']['search']['results']

        for result in results['results']:
            out_dir = sourcegraph_dir()
            with open(out_dir / f"{repo_name}_README.txt", 'w', encoding='utf-8', errors='replace') as file:
                file.write(result['file']['content'])
                print (f'Found readme for {repo_url}')

    except Exception as e:
        print(f"Error: {e}")
        return
