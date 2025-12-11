from function_match import FUNCTION_MATCH
import logging
import json
import subprocess
import os

logging.basicConfig(level=logging.INFO)

class ZERO_IN():
    def __init__(self):
        self.fm = FUNCTION_MATCH()
        self.CONFIDENCE_THRESHOLD = 8

    '''
    Goes through final GSS_results/MATCHES.json to find unique matches with confidence >= X
    '''
    def find_repos(self):
        with open('GSS_results/MATCHES.json', 'r') as f:
            data = json.load(f)

        repos = set()
        for entry in data.values():
            confidence = entry[1]
            if (confidence < self.CONFIDENCE_THRESHOLD):
                continue

            file_path = entry[0]
            
            filename = os.path.basename(file_path)

            repo_name = filename.split('_')[0]
            repos.add(repo_name)

        for repo_name in repos:
            self.download_repos(self, "TODO: get org", repo_name)

    '''
    Downloads repo with string hit from GitHub
    '''
    def download_repo(self, org: str, repo_name: str):
        os.makedirs("GSS_zeroin", exist_ok=True)

        # Build GitHub URL
        if org:
            repo_url = f"https://github.com/{github_org}/{repo_name}.git"
            target_dir = os.path.join("GSS_zeroin", f"{org}_{repo_name}")
        elif '/' in repo_name:
            # repo_name already includes org
            repo_url = f"https://github.com/{repo_name}.git"
            org, repo = repo_name.split('/')
            target_dir = os.path.join(output_dir, f"{org}_{repo}")
        else:
            logging.critical(f"Warning: No org/name specified for {repo_name}. Skipping.")
            return None
        
        try:
            logging.info(f"Downloading {repo_name}...")

            result = subprocess.run(
            ["git", "clone", repo_url, target_dir],
            capture_output=True,
            text=True,
            timeout=120
        )

        except subprocess.TimeoutExpired:
            logging.critical(f"Timedout while downloading {repo_name}")
            return None
        
        except Exception as e:
            logging.critical(f"Error downloading {repo_name}: {str(e)}")
            return None

    '''
    Procures list of functions from opensource repo
    '''
    def get_opensource_funcs(self):
        pass

    '''
    Procures list of functions from decomp
    '''
    def get_decomps(self):
        pass

    '''
    Attempts to match these functions
    '''
    def function_match(self):
        pass

    '''
    Optional: Get read me's so user can read them and decide on if a repo should be downloaded or not
    '''
    def get_readme(org, repo_name, output_path=None):
        url = f"https://api.github.com/repos/{org}/{repo_name}/readme"
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Python-Requests"
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            content_encoded = data.get("content", "")
            content_decoded = base64.b64decode(content_encoded).decode("utf-8")
            
            download_url = data.get("download_url", "")
            
            # If output_path is provided, save to file
            if output_path:
                os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
                
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content_decoded)
                
                print(f"README saved to: {output_path}")
                return output_path
            else:
                return content_decoded
                
        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
            if response.status_code == 404:
                print(f"Repository {org}/{repo_name} not found, or README doesn't exist")
            elif response.status_code == 403:
                print("Rate limit exceeded")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None