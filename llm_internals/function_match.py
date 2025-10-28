from llm_interact import LLM_INTERACT
import logging

logging.basicConfig(level=logging.INFO)

class FUNCTION_MATCH:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode) as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opening `{path}`.")
            raise e

    '''
    Return a float value out of 10 representing the similarity between the 
    decompiled function and the open source function.
    '''
    def compare_funcs(self, decomp_func_path: str, source_func_path: str) -> float:
        decomp_func = self.open_file(decomp_func_path, "r")
        source_func = self.open_file(source_func_path, "r")

        system_prompt = self.open_file("cfg/funcmatch_system.txt", "r")
        user_prompt = f"Analyze the similarity of the following functions:\nDECOMPILATION:\n{decomp_func}\n----\nOPEN-SOURCE CODE:\n{source_func}\n----"

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        response = self.LLM.query_LLM(self.MODEL, messages)

        rating = response["choices"][0]["message"]["content"]

        try:
            rating = float(rating)
        except Exception as e:
            logging.critical(f"LLM returned non-float value for {decomp_func_path} vs. {source_func_path}.")
            raise e

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


a = FUNCTION_MATCH()
b = a.find_matching_func("test_materials/C-Web-Server/test_server_decomp.txt", ["test_materials/C-Web-Server/test_server_source.txt","test_materials/C-Web-Server/test_server_actual_source.txt","test_materials/useless_func.txt"])
print(b)
