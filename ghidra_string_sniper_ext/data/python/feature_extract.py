from llm_interact import LLM_INTERACT
import logging
import json

logging.basicConfig(level=logging.INFO)

'''
The goal of this experimental class is to extract features such as function headers,
variable names, variable types, and other information from open source code to ultimately 
place into ghidra.

This feature extraction will happen between open source code and decompilation that has received
a certain confidence value during the function matching process.
'''
class FEATURE_EXTRACT:
    def __init__(self):
        self.MODEL="openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.CONFIDENCE_THRESHOLD = 8

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode) as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opeing `{path}`.")
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE"

    def extract_features(self, decomp_func_path: str, source_func_path: str):
        raise NotImplemented


    '''
    Iterate through function matching results and run suitable matches through feature extraction.
    '''
    def iterate_results(self):
        logging.info("Starting feature extraction...")

        match_file_content = self.open_file("GSS_results/MATCHES.json", "r")
        matches = json.loads(match_file_content)

        for str_hash in matches:
            source_path, confidence = matches[str_hash]

            if (confidence < self.CONFIDENCE_THRESHOLD):
                continue

            decomp_path = f"{GSS_decomps}/{str_hash}/decomp.txt"

            logging.info(f"Analyzing {source_path}")
            self.extract_features(decomp_path, source_path)

