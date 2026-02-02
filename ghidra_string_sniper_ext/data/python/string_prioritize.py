from llm_interact import LLM_INTERACT
from gss_paths import results_json_path, decomps_dir
from collections import Counter
from pathlib import Path
import subprocess
import logging
import json
import math
import re
import sys
import hashlib
import os
import re
import shutil


logging.basicConfig(level=logging.INFO)

class STRING_PRIORITIZE:
    def __init__(self):
        #self.MODEL = "openai/gpt-oss-20b:free"
        self.MODEL = "openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.MAX_STRING_COUNT = 10
        self.MAX_DEPTH = 4
        self.MAX_RETRIES = 2

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
    Returns list of strings containing common opensource signatures.
    Also removes the matched strings from the list.
    '''
    def get_opensource_strings(self, string_list: list) -> list:
        opensource_strings = {
            "openssl": ["SSL_", "TLS_", "RSA_", "EC_", "BIO_", "X509_","OPENSSL_", "EVP_", "MD5_", "SHA256_"],
            "zlib": ["zlib_version", "deflate", "inflate", "gz"],
            "libcurl": ["curl_", "CURLOPT_", "CURLINFO_"],
            "boost": ["boost::", "_bi_", "boost_"],
            "qt": ["QObject", "QString", "QtCore", "qMain"],
            "opengl": ["glEnable", "glVertex", "GL_", "glu"],
            "sqlite": ["sqlite3_", "SQLITE_"]
        }

        for catagory, patterns in opensource_strings.items():
            matches = []
            for string in string_list:
                for pattern in patterns:
                    if pattern.lower() in string.lower():
                        string_list.remove(string)
                        matches.append(string)
                        break

        return matches

    '''
    Removes common strings that will typically show up in binaries.
    These are strings that may return as high entropy, but we know are useless for our purposes.

    could this be turned into a map or something else for O(1)? `in` is a O(n) probably
    '''
    def remove_common_strings(self, string_list: list) -> list:
        common_patterns = [
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890",
            "!@#$%^&*()",
            "zyxwvutsrqponmlkjihgfedcba",
            "0987654321",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ]
        
        filtered = []
        for string in string_list:
            string_lower = string.lower()
            is_common = any(pattern in string_lower for pattern in common_patterns)
            
            if not is_common:
                filtered.append(string)
                
        return filtered
    
    '''
    Filter strings based on reasonable entropy ranges for meaningful text
    '''
    def filter_by_entropy(self, string_list: list, min_entropy=2.0, max_entropy=5.5) -> list:
        filtered = []
        for string in string_list:
            entropy = self.shannon_entropy(string)
            if min_entropy <= entropy <= max_entropy:
                filtered.append(string)
        return filtered

    '''
    Check if string has reasonable mix of character types
    '''
    def has_reasonable_character_distribution(self, string_list: list) -> list:
        filtered = []

        for string in string_list:
            alpha_count = sum(1 for c in string if c.isalpha())
            digit_count = sum(1 for c in string if c.isdigit())
            special_count = len(string) - alpha_count - digit_count
            
            # Reasonable strings should have decent alpha content
            # and not be dominated by special characters
            alpha_ratio = alpha_count / len(string)
            special_ratio = special_count / len(string)
            
            if alpha_ratio > 0.3 and special_ratio < 0.65:
                filtered.append(string)

        return filtered

    '''
    Filter out strings that match useless patterns
    '''
    def filter_patterns(self, string_list: list) -> list:
        patterns_to_filter = [
            r'^[a-z]+$',  # All lowercase sequential
            r'^[A-Z]+$',  # All uppercase sequential  
            r'^[0-9]+$',  # All digits
            r'^[!-~]+$',  # All printable ASCII in order
            r'^[A-Za-z0-9!-~]+$',  # All printable ASCII ranges
            r'^(.{1,3})\1+$',  # Repeated short sequences
        ]
        
        filtered = []
        for string in string_list:
            is_bad_pattern = any(re.match(pattern, string) for pattern in patterns_to_filter)
            
            if not is_bad_pattern:
                filtered.append(string)
                
        return filtered

    '''
    For now, uses strings for ease of development/testing.
    TODO: Connect with ghidra to get strings from it.
        - less dependancies. 
        - this is a ghidra extension ultimately, so why not use ghidra instead of strings

    Get strings, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings(self, binpath: str) -> list:
        strings_bin = shutil.which("strings")
        if strings_bin:
            cmd = [strings_bin, "-a", "-n", "4", binpath]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            stdout = result.stdout
            string_list = stdout.split("\n")
        else:
            string_list = self.extract_strings_from_binary(binpath)

        string_list = self.remove_common_strings(string_list)
        string_list = self.filter_patterns(string_list) 
        string_list = self.filter_by_entropy(string_list)
        string_list = self.has_reasonable_character_distribution(string_list)
        string_list = self.get_shannon_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list
    
    '''
    Get strings from stdin, do non-LLM prioritization, then return a curated list of strings to pass to LLM
    '''
    def get_strings_stdin(self) -> list:
        print("Enter strings:")
        string_list = [line.rstrip() for line in sys.stdin]

        string_list = self.remove_common_strings(string_list)
        string_list = self.filter_patterns(string_list) 
        string_list = self.filter_by_entropy(string_list)
        string_list = self.has_reasonable_character_distribution(string_list)
        string_list = self.get_shannon_list(string_list)
        string_list = string_list[:self.MAX_STRING_COUNT]

        return string_list

    '''
    Cross-platform fallback string extractor (ASCII printable sequences).
    '''
    def extract_strings_from_binary(self, binpath: str, min_len: int = 4) -> list:
        try:
            with open(binpath, "rb") as f:
                data = f.read()
        except Exception as e:
            logging.error(f"Failed to read binary for string extraction: {e}")
            return []

        strings = []
        buf = bytearray()
        for b in data:
            if 32 <= b <= 126:
                buf.append(b)
                continue
            if len(buf) >= min_len:
                strings.append(buf.decode("ascii", errors="ignore"))
            buf.clear()

        if len(buf) >= min_len:
            strings.append(buf.decode("ascii", errors="ignore"))

        return strings
    

    '''
    Simply retrieve a text file's contents.
    '''
    def get_prompt(self, prompt_path: str) -> str:
        try:
            with open(prompt_path, "r", encoding="utf-8", errors="replace") as f:
                return (f.read())
        except Exception as e:
            logging.critical(f"Getting prompt `{prompt_path}` failed.")
            raise e


    '''
    Given a binary path, extract all strings from ghidra, perform non-LLM heuristics to 
    order them and then pass into an LLM query for final reordering.
    '''
    def prioritize_strings(self, binpath: str, lang: str=None, retries: int=0):
        system_prompt = self.get_prompt("cfg/strprioritize_system.txt")
        string_list = self.get_ghidra_strings(binpath, lang=lang)
        user_prompt = str(string_list)

        messages = [
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}
        ]

        logging.info("Starting reordering LLM query...")

        response = self.LLM.query_LLM(self.MODEL, messages, [])
        try:
            content = response["choices"][0]["message"]["content"].split("\n")
        except:
            if (retries >= self.MAX_RETRIES):
                raise e
            else:
                logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")

                tries = retries
                language = lang 
                self.prioritize_strings(binpath, lang=language, retries=tries+1)


        #TODO THIS SHOULD NOT BE USING STRING SPLICING. AT LEAST SPLIT THE STRING AND GRAB THE LAST PART OR SOMETHING
        # WILL FIX LATER

        output = {}
        logging.info(content)
        for string in content:
            string = string.split("--GSS_DELIM--")

            actual_string = string[0]
            actual_string = self.normalize_string(actual_string)
            folder_name = actual_string.encode("utf-8")
            md5_hash = hashlib.md5()
            md5_hash.update(folder_name)
            folder_name = str(md5_hash.hexdigest())
            
            try:
                confidence_value = int(string[1])
            except ValueError as e:
                if (retries >= self.MAX_RETRIES):
                    raise e
                else:
                    logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")

                    tries = retries
                    language = lang 
                    self.prioritize_strings(binpath, lang=language, retries=tries+1)

            output[string[0]] = {
                    "confidence" : int(string[1]),
                    "entropy" : self.shannon_entropy(string[0]),
                    "hash": folder_name
            }
         
        out_path = results_json_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2)

        return response

    '''
    Get strings using Pyghidra API.
    Also, run non-LLM heuristics on the strings.
    Once strings are ordered by said heuristics, extract decompiled code from Ghidra for each string
    '''
    def get_ghidra_strings(self, binary_path: str, lang: str=None) -> list[str]:
        logging.info("Loading binary into ghidra..")
        try:
            import pyghidra
        except Exception as e:
            raise ModuleNotFoundError("pyghidra is not available") from e

        with pyghidra.open_program(binary_path, analyze=True, language=lang) as flat_api:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            program = flat_api.getCurrentProgram()

            logging.info(f"Analyzing: {program.getName()}")
            logging.info(f"Language: {program.getLanguageID()}")

            logging.info(f"Getting all strings...")

            string_mgr = program.getListing().getDefinedData(True)
            string_count = 0

            string_list = []
            string_addrs = {}
            for data in string_mgr:
                if not data.hasStringValue():
                    continue
                addr = data.getAddress()
                string_val = data.getValue()
                string_addr = data.getAddress()

                string_list.append(string_val)
                string_addrs[string_val] = string_addr

            logging.info("Running non-LLM heuristics...")

            string_list = self.remove_common_strings(string_list)
            string_list = self.filter_patterns(string_list) 
            string_list = self.filter_by_entropy(string_list)
            string_list = self.has_reasonable_character_distribution(string_list)
            string_list = self.get_shannon_list(string_list)
            string_list = string_list[:self.MAX_STRING_COUNT]

            #get decomp for all the prioritized strings

            logging.info("Getting decomp for non-LLM ordered strings...")

            for string in string_list:
                str_addr = string_addrs[string]
                references = flat_api.getReferencesTo(str_addr)

                if (not references):
                    logging.critical(f"No references to '{string}' found.")
                    continue

                decompiler = DecompInterface()
                decompiler.openProgram(program)

                seen_functions = set()

                all_decomp = ""
                for ref in references:
                    from_addr = ref.getFromAddress()
                    function = flat_api.getFunctionContaining(from_addr)

                    #look for nested function references
                    if (not function):
                        logging.info("Calling recursive reference search.")
                        function = self.search_for_function(flat_api, from_addr, 0)
                    
                    if (not function or function in seen_functions):
                        continue

                    seen_functions.add(function)

                    logging.info(f"Found function: {function.getName()}")
                    logging.info(f"Decompiling {function.getName()}...")

                    result = decompiler.decompileFunction(function, 30, ConsoleTaskMonitor())

                    if result.decompileCompleted():
                        decomp_code = result.getDecompiledFunction().getC()
                        all_decomp += f"{decomp_code}\n\n"
                    else:
                        logging.info(f"Decomp failed for {function.getName()}")

                string = self.normalize_string(string)
                folder_name = string.encode("utf-8")
                md5_hash = hashlib.md5()
                md5_hash.update(folder_name)
                folder_name = str(md5_hash.hexdigest())
                decomp_root = decomps_dir()
                target_dir = decomp_root / folder_name
                target_dir.mkdir(parents=True, exist_ok=True)
                with open(target_dir / "decomp.txt", "w") as file:
                    file.write(all_decomp)

            return string_list

    def search_for_function(self, flat_api, addr, ctr):
        if (ctr >= self.MAX_DEPTH):
            return None

        references = flat_api.getReferencesTo(addr)
        for ref in references:
            from_addr = ref.getFromAddress()
            function = flat_api.getFunctionContaining(from_addr)

            if (not function):
                return self.search_for_function(flat_api, from_addr, ctr+1)
            else:
                logging.info("Recursive search found function.")
                return function


    def normalize_string(self, s: str) -> str:
        s = s.replace("\\n","").replace("\\t","").replace("\\r","")
        return re.sub(r"\s+","",s)
