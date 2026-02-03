from llm_interact import LLM_INTERACT
from gss_paths import matches_json_path, decomps_dir
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
        self.MODEL="openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.CONFIDENCE_THRESHOLD = 8

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode, encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opeing `{path}`.")
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE"

    def extract_features(self, str_hash: str, decomp_func_path: str, source_func_path: str):
        final_content = ""

        decomp_func = self.open_file(decomp_func_path, "r")
        source_func = self.open_file(source_func_path, "r")

        #FUNCTION SIGNATURES

        system_prompt = self.open_file("cfg/featext_system.txt", "r")
        user_prompt = f"Extract features from the following functions:\nDECOMPILATION:\n{decomp_func}\n---\nOPEN-SOURCE CODE:\n{source_func}\n---"
        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]
        response = self.LLM.query_LLM(self.MODEL, messages)
        content = response["choices"][0]["message"]["content"]
        final_content = final_content + content + "\n"

        #VARIABLE NAMES

        system_prompt = self.open_file("cfg/featext_system.txt", "r")
        user_prompt = f"Extract features from the following functions:\nDECOMPILATION:\n{decomp_func}\n---\nOPEN-SOURCE CODE:\n{source_func}\n---"
        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]
        response = self.LLM.query_LLM(self.MODEL, messages)
        content = response["choices"][0]["message"]["content"]
        final_content = final_content + content + "\n"

        fpath = decomps_dir() / str_hash / "EXTRACTIONS.txt"
        with open(fpath, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
            logging.info(f"Wrote proposals to {fpath}")


    '''
    Iterate through function matching results and run suitable matches through feature extraction.
    '''
    def iterate_results(self):
        logging.info("Starting feature extraction...")

        match_file_content = self.open_file(str(matches_json_path()), "r")
        matches = json.loads(match_file_content)

        for str_hash in matches:
            source_path, confidence = matches[str_hash]

            if (confidence < self.CONFIDENCE_THRESHOLD):
                continue

            decomp_path = str(decomps_dir() / str_hash / "decomp.txt")

            logging.info(f"Analyzing {source_path}")
            self.extract_features(str_hash, decomp_path, source_path)
