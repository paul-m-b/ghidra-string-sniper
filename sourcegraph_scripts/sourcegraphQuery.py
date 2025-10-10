import requests
import hashlib
import json
import time
import sys
import os


"""
Queries sourcegraph for public repositories containing strings in specified input file, creates folder named GSS_results
containing the returned file contents from sourcegraph with a small header containing the line number of the matches.
Also calls get_readme if 4th argument is true.
"""
def get_repos(input_file_name: str, operator: str, match_count: str, find_readme: str) -> set():
    with open(input_file_name, 'r') as file:
        query: str = file.read()

    if (operator.lower() == "and"):
        query = query.replace(' ', ' AND ')
    if (operator.lower() == "or"):
        query = query.replace(' ', ' OR ')


    query_filtered = f'type:file lang:c++ lang:c count:{match_count} {query}'

    url: str = "https://sourcegraph.com/.api/graphql"
    
    payload: dict = {
        "query": f'''
        {{
            search(query: "{query_filtered}", version: V2) {{
                results {{
                    resultCount
                    results {{
                        __typename
                        ... on FileMatch {{
                            repository {{
                                name
                            }}
                            file {{
                                name
                                content
                            }}
                            lineMatches {{
                                lineNumber
                            }}
                        }}
                    }}
                }}
            }}
        }}
        '''
    }

    print (f"\nSearching for {query}")
    
    try:
        response: Response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()

        results = data['data']['search']['results']
        result_count = results['resultCount']
        
        repos = set()
        for match in results['results']:
            if match['__typename'] == 'FileMatch' and match['repository']:
                print (f"{match['repository']['name']} in file {match['file']['name']}")
                repos.add(match['repository']['name'])

                # List of line numbers with matches
                matched_lines = set(match['lineNumber'] for match in match['lineMatches'])
                line_matches = match['lineMatches']

                matched_file: str = match['file']['name'].split('.')[0]
                repo_name: str = match['repository']['name'].split('/')[-1]
                file_name: str = repo_name + '_' + matched_file + '.txt'

                match_msg: str = ""
                for num in matched_lines:
                    match_msg += str(num+6) + " "

                os.makedirs("GSS_results/", exist_ok=True)

                with open("GSS_results/"+file_name, 'w') as file:
                    file.write("-----------GSS-----------\n" + "query: " + query + "\n" + match_msg + "\n-------------------------\n\n" + match['file']['content'])


                # Now find the readme if specified:
                if (find_readme == 'true'):
                    get_readme(match['repository']['name'])

        print(f"\nSourcegraph found {result_count} matches from {len(repos)} repo(s):")
        
        return repos
        
    except Exception as e:
        print(f"Error: {e}")
        return []


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
        response: Response = requests.post(url, json=payload, timeout=30)
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


# Examples: python3 sourcegraphQuery.py input.txt AND ALL true
#           python3 sourcegraphQuery.py input.txt OR 125 false

repos: set() = get_repos(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
for repo in repos:
    print (f"   - {repo}")