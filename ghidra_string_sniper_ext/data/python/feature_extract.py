from llm_interact import LLM_INTERACT
from gss_paths import matches_json_path, decomps_dir
import logging
import json
import time

logging.basicConfig(level=logging.INFO)

'''
The goal of this experimental class is to extract features such as function headers,
variable names, variable types, and other information from open source code to ultimately 
place into Ghidra.

Feature extraction is run on pairs of:
    - Ghidra decompilation
    - Open-source code file

And only for matches scoring above CONFIDENCE_THRESHOLD.
'''

class FEATURE_EXTRACT:
    def __init__(self):
        self.MODEL = "openai/gpt-oss-20b:free"
        self.LLM = LLM_INTERACT()
        self.CONFIDENCE_THRESHOLD = 8

        # Retry settings
        self.MAX_RETRIES = 5
        self.RETRY_BACKOFF = 2.0  # seconds added per attempt

    # ------------------------------------------------------------
    # Safe File Reader
    # ------------------------------------------------------------
    def open_file(self, path: str, mode: str) -> str:
        try:
            with open(path, mode, encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            logging.critical(f"Error opening `{path}`: {e}")
            return "NO FILE CONTENT REPORTED. ASSUME NO CODE"

    # ------------------------------------------------------------
    # LLM wrapper with retry & error handling
    # ------------------------------------------------------------
    def safe_query(self, messages):
        """
        Calls the LLM with retry and proper error/malformed handling.
        Always returns either:
            { "choices": [...] }
        OR:
            { "error": "...reason..." }
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self.LLM.query_LLM(self.MODEL, messages)

                # Normal success case
                if isinstance(resp, dict) and "choices" in resp:
                    return resp

                # API returned explicit error
                if isinstance(resp, dict) and "error" in resp:
                    err_msg = str(resp["error"]).lower()
                    logging.warning(f"LLM returned error: {resp}")

                    # Retry on soft errors
                    if any(x in err_msg for x in ("rate", "limit", "busy", "overloaded", "timeout")):
                        wait = 1 + attempt * self.RETRY_BACKOFF
                        logging.warning(f"Retrying LLM in {wait}s...")
                        time.sleep(wait)
                        continue

                    # Hard error means no retry
                    return resp

                # Response is corrupted/malformed
                logging.error(f"Malformed LLM response: {resp}")
                wait = 1 + attempt * self.RETRY_BACKOFF
                logging.warning(f"Retrying after malformed response in {wait}s...")
                time.sleep(wait)
                continue

            except Exception as e:
                logging.error(f"Exception during LLM query: {e}")
                wait = 1 + attempt * self.RETRY_BACKOFF
                logging.warning(f"Retrying after exception in {wait}s...")
                time.sleep(wait)

        # After MAX_RETRIES, give up
        return {"error": "retry_exhausted"}

    # ------------------------------------------------------------
    # Feature Extraction Logic
    # ------------------------------------------------------------
    def extract_features(self, str_hash: str, decomp_func_path: str, source_func_path: str):
        decomp_func = self.open_file(decomp_func_path, "r")
        source_func = self.open_file(source_func_path, "r")

        system_prompt = self.open_file("cfg/featext_system.txt", "r")

        user_prompt = (
            "Extract features from the following functions:\n"
            f"DECOMPILATION:\n{decomp_func}\n---\n"
            f"OPEN-SOURCE CODE:\n{source_func}\n---"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        # ---------- SAFE QUERY ----------
        response = self.safe_query(messages)

        # LLM failed completely
        if "choices" not in response:
            logging.error(f"Feature extraction failed for {str_hash}: {response}")
            fpath = f"GSS_decomps/{str_hash}/EXTRACTIONS.txt"
            with open(fpath, "w") as f:
                f.write("LLM FAILED TO GENERATE FEATURES.\n")
            return

        # Extract text from the model
        content = response["choices"][0]["message"]["content"]

        # Save extraction output
        fpath = f"GSS_decomps/{str_hash}/EXTRACTIONS.txt"
        try:
            with open(fpath, "w") as f:
                f.write(content)
            logging.info(f"Wrote feature extraction to {fpath}")
        except Exception as e:
            logging.error(f"Error writing extraction file: {e}")

    # ------------------------------------------------------------
    # Run extraction on MATCHES.json
    # ------------------------------------------------------------
    def iterate_results(self):
        logging.info("Starting feature extraction...")

        match_file_content = self.open_file(str(matches_json_path()), "r")

        try:
            matches = json.loads(match_file_content)
        except Exception as e:
            logging.critical(f"Failed to parse MATCHES.json: {e}")
            return

        for str_hash in matches:
            source_path, confidence = matches[str_hash]

            if confidence < self.CONFIDENCE_THRESHOLD:
                continue

            decomp_path = str(decomps_dir() / str_hash / "decomp.txt")

            logging.info(f"Analyzing {source_path}")
            self.extract_features(str_hash, decomp_path, source_path)
