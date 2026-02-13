from llm_interact import LLM_INTERACT
from gss_paths import results_json_path
from collections import Counter
from pathlib import Path
import logging
import json
import math
import re
import hashlib
import os

logging.basicConfig(level=logging.INFO)


class STRING_PRIORITIZE:
    def __init__(self):
        #self.MODEL = "openai/gpt-oss-20b:free"
        self.MODEL = "openai/gpt-4o-mini"
        self.LLM = LLM_INTERACT()
        self.MAX_STRING_COUNT = 10
        self.MAX_RETRIES = 2

    def shannon_entropy(self, s: str):
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def get_shannon_list(self, string_list: list) -> list:
        shannon_dict = {}
        for string in string_list:
            shannon_dict[string] = self.shannon_entropy(string)
        return sorted(shannon_dict, key=shannon_dict.get, reverse=True)

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

    def filter_by_entropy(self, string_list: list, min_entropy=2.0, max_entropy=5.5) -> list:
        filtered = []
        for string in string_list:
            entropy = self.shannon_entropy(string)
            if min_entropy <= entropy <= max_entropy:
                filtered.append(string)
        return filtered

    def has_reasonable_character_distribution(self, string_list: list) -> list:
        filtered = []
        for string in string_list:
            alpha_count = sum(1 for c in string if c.isalpha())
            digit_count = sum(1 for c in string if c.isdigit())
            special_count = len(string) - alpha_count - digit_count

            alpha_ratio = alpha_count / len(string)
            special_ratio = special_count / len(string)

            if alpha_ratio > 0.3 and special_ratio < 0.65:
                filtered.append(string)
        return filtered

    def filter_patterns(self, string_list: list) -> list:
        patterns_to_filter = [
            r'^[a-z]+$',
            r'^[A-Z]+$',
            r'^[0-9]+$',
            r'^[!-~]+$',
            r'^[A-Za-z0-9!-~]+$',
            r'^(.{1,3})\1+$',
        ]

        filtered = []
        for string in string_list:
            is_bad_pattern = any(re.match(pattern, string) for pattern in patterns_to_filter)
            if not is_bad_pattern:
                filtered.append(string)
        return filtered

    def select_strings(self, string_list: list) -> list:
        if not string_list:
            return []
        cleaned = [s for s in string_list if isinstance(s, str) and s.strip()]
        cleaned = self.remove_common_strings(cleaned)
        cleaned = self.filter_patterns(cleaned)
        cleaned = self.filter_by_entropy(cleaned)
        cleaned = self.has_reasonable_character_distribution(cleaned)
        cleaned = self.get_shannon_list(cleaned)
        return cleaned[:self.MAX_STRING_COUNT]

    def get_prompt(self, prompt_path: str) -> str:
        p = Path(prompt_path)
        if not p.exists():
            p = Path(__file__).parent / prompt_path
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Getting prompt `{prompt_path}` failed.")
            raise e

    def normalize_string(self, s: str) -> str:
        s = s.replace("\\n", "").replace("\\t", "").replace("\\r", "")
        return re.sub(r"\s+", "", s)

    def compute_hash(self, s: str) -> str:
        normalized = self.normalize_string(s)
        md5_hash = hashlib.md5()
        md5_hash.update(normalized.encode("utf-8"))
        return md5_hash.hexdigest()

    def prioritize_strings_list(self, string_list: list, retries: int = 0):
        system_prompt = self.get_prompt("cfg/strprioritize_system.txt")
        curated = self.select_strings(string_list)
        id_to_string = {str(i): s for i, s in enumerate(curated)}
        user_prompt = "\n".join([f"{i}: {s}" for i, s in enumerate(curated)])

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        logging.info("Starting reordering LLM query...")

        response = self.LLM.query_LLM(self.MODEL, messages, [])
        try:
            content = response["choices"][0]["message"]["content"].split("\n")
        except Exception as e:
            if retries >= self.MAX_RETRIES:
                raise e
            logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")
            return self.prioritize_strings_list(string_list, retries=retries + 1)

        output = {}
        normalized_map = {self.normalize_string(s): s for s in curated}
        logging.info(content)
        for line in content:
            if "--GSS_DELIM--" not in line:
                continue
            parts = line.split("--GSS_DELIM--", 1)
            raw = parts[0].strip()
            score_text = parts[1].strip()
            if not raw:
                continue

            try:
                confidence_value = int(score_text)
            except ValueError as e:
                if retries >= self.MAX_RETRIES:
                    raise e
                logging.critical(f"LLM Failure. Restarting Prioritize Strings.\n\t{e}")
                return self.prioritize_strings_list(string_list, retries=retries + 1)

            string_value = None
            match = re.search(r"\b(\d+)\b", raw)
            if match and match.group(1) in id_to_string:
                string_value = id_to_string[match.group(1)]
            elif raw in id_to_string:
                string_value = id_to_string[raw]
            elif raw in curated:
                string_value = raw
            else:
                normalized = self.normalize_string(raw)
                string_value = normalized_map.get(normalized)

            if string_value is None:
                logging.warning("LLM returned unknown id/string: %s", raw)
                continue

            output[string_value] = {
                "confidence": confidence_value,
                "entropy": self.shannon_entropy(string_value),
                "hash": self.compute_hash(string_value)
            }

        out_path = results_json_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        return response

    '''
    Get strings using Pyghidra API.
    Also, run non-LLM heuristics on the strings.
    Once strings are ordered by said heuristics, extract decompiled code from Ghidra for each string
    '''
    def get_ghidra_strings(self, binary_path: str, lang: str=None) -> list[str]:
        logging.info("Loading binary into ghidra..")
        with pyghidra.open_program(binary_path, analyze=True, language=lang) as flat_api:
            logging.info("OPENED PROPERLY")
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
                os.makedirs(f"GSS_decomps/{folder_name}/", exist_ok=True)
                with open(f"GSS_decomps/{folder_name}/decomp.txt", "w") as file:
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

        return output
