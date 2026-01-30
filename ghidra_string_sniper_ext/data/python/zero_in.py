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
