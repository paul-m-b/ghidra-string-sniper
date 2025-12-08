from function_match import FUNCTION_MATCH
import logging
import json
import os

logging.basicConfig(level=logging.INFO)

class ZERO_IN():
    def __init__(self):
        self.fm = FUNCTION_MATCH()
        self.CONFIDENCE_THRESHOLD = 8

    '''
    Goes through final GSS_results/MATCHES.json to find matches with confidence >= X
    '''
    def find_repos(self):
        with open('GSS_results/MATCHES.json', 'r') as f:
            data = json.load(f)

        repos = set()
        for entry in data.values():
            file_path = entry[0]
            
            filename = os.path.basename(file_path)

    '''
    Downloads repo with string hit from GitHub
    '''
    def download_repos(self):
        pass

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