from llm_interact import LLM_INTERACT
import subprocess

class STRING_PRIORITIZE:
    def __init__(self):
        pass

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

        return string_list

    def prioritize_strings(self):
        pass

