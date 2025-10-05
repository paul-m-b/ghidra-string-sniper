from llm_interact import LLM_INTERACT
import subprocess
import logging
import json

class STRING_PRIORITIZE:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()

    '''
    For now, uses strings for ease of development/testing.
    TODO: Connect with ghidra to get strings from it.
        - less dependancies. 
        - this is a ghidra extension ultimately, so why not use ghidra instead of strings
    '''
    def get_strings(self, binpath: str) -> list:
        cmd = ["strings",binpath]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stdout = result.stdout
        string_list = stdout.split("\n")

        

        return string_list[:1000]
        #return string_list

    def get_prompt(self, prompt_path: str) -> str:
        try:
            with open(prompt_path, "r") as f:
                return (f.read())
        except Exception as e:
            logging.critical(f"Getting prompt `{prompt_path}` failed.")
            raise e



    def prioritize_strings(self, binpath: str):
        system_prompt = self.get_prompt("cfg/strprioritize_system.txt")
        user_prompt = str(self.get_strings(binpath))
        response_format = json.loads(self.get_prompt("cfg/strprioritize_response.json"))

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        response = self.LLM.query_LLM(self.MODEL, messages, [], response_format)

        return response

a = STRING_PRIORITIZE()
b = a.prioritize_strings("core_ets2mp.dll")

content = b["choices"][0]["message"]["content"]
content_json = json.loads(content)
print(content_json["sorted_string_list"])
print(len(content_json["sorted_string_list"]))
