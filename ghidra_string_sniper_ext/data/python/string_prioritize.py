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
        user_prompt = str(curated)

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

            output[raw] = {
                "confidence": confidence_value,
                "entropy": self.shannon_entropy(raw),
                "hash": self.compute_hash(raw)
            }

        out_path = results_json_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        return output

    # Legacy helpers removed: get_strings / get_strings_stdin
