from llm_interact import LLM_INTERACT
import logging
import os
import json
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO)

class FUNCTION_MATCH:
    def __init__(self):
        self.MODEL = "openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.MAX_RETRIES = 3

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode) as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opening `{path}`.")
            #raise e
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE AND RETURN RATING OF 0."

    '''
    Return a float value out of 10 representing the similarity between the 
    decompiled function and the open source function.
    '''
    def compare_funcs(self, decomp_func_path: str, source_func_path: str, retries: int=0) -> float:
        decomp_func = self.open_file(decomp_func_path, "r")
        source_func = self.open_file(source_func_path, "r")

        system_prompt = self.open_file("cfg/funcmatch_system.txt", "r")
        user_prompt = f"Analyze the similarity of the following functions:\nDECOMPILATION:\n{decomp_func}\n----\nOPEN-SOURCE CODE:\n{source_func}\n----"

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        response = self.LLM.query_LLM(self.MODEL, messages)

        try:
            rating = response["choices"][0]["message"]["content"]
            rating = float(rating)
        except Exception as e:
            logging.critical(f"LLM returned unexpected value for {decomp_func_path} vs. {source_func_path}.")

            if ("rate-limit" in response):
                logging.info("Being rate limited. Trying again in 2 seconds.")
                time.sleep(2)
                self.compare_funcs(decomp_func_path, source_func_path)
            elif retries < self.MAX_RETRIES:
                logging.critical("Unkown error. Retrying function match.")

                tries = retries
                self.compare_funcs(decomp_func_path, source_func_path, retries=tries+1)
            else:
                logging.critical("Retries reached. Rating set to zero.")
                rating = 0

        return rating



    '''
    Given a list of candidate open-source functions, will return the one that is most similar to 
    the provided decomp.
    '''
    def find_matching_func(self, decomp_func_path: str,
                           source_func_candidates: list[str]) -> list[str,float]:
        max_rating = -1
        match_func_path = ""

        for source_path in source_func_candidates:
            rating = self.compare_funcs(decomp_func_path, source_path)

            logging.info(f"{source_path}: {rating}")

            if (rating == max_rating):
                # this function has the same rating as the previous max
                # potentially max an LLM call here to decide between the two.
                logging.info(f"Functionality not implemented. {match_func_path} and {source_path} received same rating of {max_rating}")

            elif (rating > max_rating):
                max_rating = rating
                match_func_path = source_path


        return [match_func_path, max_rating]

    '''
    Iterate thruogh GSS_Results and get function match results for each.
    Each folder contains open source code related to a particular string.
    '''
    def iterate_through_results(self):
        out_dict = {}
        root = Path("./GSS_results")
        for dirpath, dirnames, filenames in os.walk(root):
            if (dirpath == "GSS_results"):
                continue
            for ind, fname in enumerate(filenames):
                filenames[ind] = dirpath+"/"+fname

            directory = dirpath.split("/")[1]
            decomp_path = f"GSS_decomps/{directory}/decomp.txt"

            match_results = self.find_matching_func(decomp_path, filenames)
            out_dict[directory] = match_results
        
        with open("./GSS_results/MATCHES.json", "w") as f:
            json.dump(out_dict, f, indent=4)

