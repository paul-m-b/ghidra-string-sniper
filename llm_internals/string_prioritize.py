from llm_interact import LLM_INTERACT
from collections import Counter
import subprocess
import logging
import json
import math

class STRING_PRIORITIZE:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.MAX_STRING_COUNT = 50

    '''
    Calculate the shannon entropy for a particular string.
    '''
    def shannon_entropy(self, s: str):
        if not s: return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c/n) * math.log2(c/n) for c in counts.values())

    '''
    Calculate the shannon entropy for each string and return its sorted form.
    '''
    def get_shannon_list(self, string_list: list) -> list:
        shannon_dict = {}
        for string in string_list:
            shannon_dict[string] = self.shannon_entropy(string)
        sorted_strings = sorted(shannon_dict, key=shannon_dict.get, reverse=True)

        return sorted_strings

    '''
    Removes common strings that will typically show up in binaries.
    These are strings that may return as high entropy, but we know are useless for our purposes.

    could this be turned into a map or something else for O(1)? `in` is a O(n) probably
    '''
    def remove_common_strings(self, string_list: list) -> list:
        common_strings = [
            "abcdefghijklmnopqrstuvwxyz",
            "123456789",
            "qwertyui",
            "zyxwvutsrqponmlkjihgfedcba",
            "987654321",
            "iuytrewq"
        ]

        modified_strings = list(string_list)
        for string in string_list:
            for common in common_strings:
                if (common in string.lower()):
                    try:
                        modified_strings.remove(string)
                    except:
                        continue

        return modified_strings


    '''
    For now, uses strings for ease of development/testing.
    TODO: Connect with ghidra to get strings from it.
        - less dependancies. 
        - this is a ghidra extension ultimately, so why not use ghidra instead of strings

    Get strings, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings(self, binpath: str) -> list:
        cmd = ["strings","-a","-n","4",binpath]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stdout = result.stdout
        string_list = stdout.split("\n")

        string_list = self.remove_common_strings(string_list)
        string_list = self.get_shannon_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list

    '''
    Simply retrieve a text file's contents.
    '''
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

        response = self.LLM.query_LLM(self.MODEL, messages, [])

        return response

a = STRING_PRIORITIZE()
b = a.prioritize_strings("./core_ets2mp.dll")
print(b["choices"][0]["message"]["content"])

