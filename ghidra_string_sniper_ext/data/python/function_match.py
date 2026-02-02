import json
import logging
import os
import time
from pathlib import Path

from llm_interact import LLM_INTERACT
from gss_paths import matches_json_path, sourcegraph_dir, decomps_dir

logging.basicConfig(level=logging.INFO)


class FUNCTION_MATCH:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.MAX_RETRIES = 3
        self.matches_path = matches_json_path()
        logging.info("[FUNCTION_MATCH] MATCHES.json will be written to: %s", self.matches_path)

    # -------------------------------------------------------------------

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode, encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            logging.critical(f"Error opening `{path}`.")
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE."

    # -------------------------------------------------------------------

    def compare_funcs(self, decomp_func_path: str, source_func_path: str, retries: int = 0) -> float:
        decomp = self.open_file(decomp_func_path, "r")
        source = self.open_file(source_func_path, "r")
        system_prompt = self.open_file("cfg/funcmatch_system.txt", "r")

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content":
                f"Analyze the similarity of the following functions:\n"
                f"DECOMPILATION:\n{decomp}\n----\n"
                f"OPEN-SOURCE CODE:\n{source}\n----"
            }
        ]

        response = self.LLM.query_LLM(self.MODEL, messages)

        # --- FIX: Handle API failure cases (no "choices") ---
        if not isinstance(response, dict) or "choices" not in response:
            logging.error(f"Bad LLM response: {response}")

            if retries < self.MAX_RETRIES:
                time.sleep(1)
                return self.compare_funcs(decomp_func_path, source_func_path, retries + 1)

            return 0.0

        try:
            rating = float(response["choices"][0]["message"]["content"])
        except Exception:
            logging.error("Unexpected response format. Falling back to rating 0.")
            return 0.0

        return rating

    # -------------------------------------------------------------------

    def find_matching_func(self, decomp_func_path: str,
                           source_func_candidates: list[str]) -> list[str, float]:
        best_rating = -1
        best_path = ""

        for src in source_func_candidates:
            rating = self.compare_funcs(decomp_func_path, src)
            logging.info(f"{src}: {rating}")

            if rating > best_rating:
                best_rating = rating
                best_path = src

        return [best_path, best_rating]

    # -------------------------------------------------------------------

    def iterate_through_results(self):
        out_dict = {}
        root = sourcegraph_dir()
        decomp_root = decomps_dir()

        for dirpath, dirnames, filenames in os.walk(root):
            if Path(dirpath) == root:
                continue

            filenames = [os.path.join(dirpath, f) for f in filenames]
            directory = Path(dirpath).name
            decomp_path = decomp_root / directory / "decomp.txt"
            if not decomp_path.exists():
                logging.warning("Missing decomp for %s; skipping match.", directory)
                out_dict[directory] = ["", 0.0]
                continue

            out_dict[directory] = self.find_matching_func(str(decomp_path), filenames)

        with open(self.matches_path, "w") as f:
            json.dump(out_dict, f, indent=4)

        logging.info("[DONE] MATCHES.json saved to: %s", self.matches_path)
        print(f"[OUTPUT] MATCHES.json path: {self.matches_path}")
