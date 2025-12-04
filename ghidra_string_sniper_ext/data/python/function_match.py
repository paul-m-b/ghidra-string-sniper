from llm_interact import LLM_INTERACT
import logging
import os
import json
import time
from pathlib import Path
import tempfile
import subprocess

logging.basicConfig(level=logging.INFO)


def get_windows_temp_path():
    """
    Ensures MATCHES.json is always written to the *Windows* temp directory,
    even when executed inside WSL.
    """
    try:
        # Run Windows PowerShell to get the real Windows %TEMP%
        win_temp = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-Command", "[IO.Path]::GetTempPath()"],
            text=True
        ).strip()

        # Convert C:\path → /mnt/c/path
        if win_temp[1] == ":":
            drive = win_temp[0].lower()
            path = win_temp[2:].replace("\\", "/")
            return Path(f"/mnt/{drive}{path}")

        return Path(win_temp)

    except Exception:
        # Fallback if powershell is unavailable
        return Path(tempfile.gettempdir())


class FUNCTION_MATCH:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.MAX_RETRIES = 3

        # === ALWAYS USE WINDOWS TEMP (even inside WSL) ===
        temp_root = get_windows_temp_path()
        self.temp_dir = temp_root / "GSS_matches"
        self.temp_dir.mkdir(exist_ok=True)

        self.temp_matches_path = self.temp_dir / "MATCHES.json"

        # === PROJECT LOCATION FOR Linux / WSL scripts ===
        self.project_matches_path = Path("./GSS_results/MATCHES.json")

        logging.info(
            f"[FUNCTION_MATCH] MATCHES.json will be written to:\n"
            f"  WINDOWS TEMP: {self.temp_matches_path}\n"
            f"  PROJECT:      {self.project_matches_path}"
        )

    # -------------------------------------------------------------------

    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode) as f:
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
        root = Path("./GSS_results")

        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath == "GSS_results":
                continue

            filenames = [os.path.join(dirpath, f) for f in filenames]
            directory = dirpath.split("/")[1]
            decomp_path = f"GSS_decomps/{directory}/decomp.txt"

            out_dict[directory] = self.find_matching_func(decomp_path, filenames)

        # === WRITE TO WINDOWS TEMP FOR GHIDRA ===
        with open(self.temp_matches_path, "w") as f:
            json.dump(out_dict, f, indent=4)

        # === WRITE TO PROJECT FOLDER FOR WSL ===
        with open(self.project_matches_path, "w") as f:
            json.dump(out_dict, f, indent=4)

        logging.info("[DONE] MATCHES.json saved to:\n"
                     f"  WINDOWS TEMP: {self.temp_matches_path}\n"
                     f"  PROJECT:      {self.project_matches_path}")

        print(f"[OUTPUT] MATCHES.json path: {self.temp_matches_path}")
