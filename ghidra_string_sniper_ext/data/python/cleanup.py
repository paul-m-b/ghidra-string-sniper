import os 
import shutil
import json
import logging
import glob
import sys

logging.basicConfig(level=logging.INFO)

class CLEANUP:

    def open_json(self, path: str):
        with open(path, "r") as file:
            data = json.load(file)
        return data

    def remove_files(self, path_list):

        for p in path_list:
            if os.path.isfile(p):
                logging.info(f"Removing file: {p}")
                os.remove(p)
            elif os.path.isdir(p):
                logging.info(f"Removing directory: {p}")
                shutil.rmtree(p)
            else:
                logging.info(f"Trying glob remove for: {p}")
                self.glob_remove(p)

    def glob_remove(self, pattern):
        for p in glob.glob(pattern):
            if os.path.isfile(p):
                logging.info(f"Removing file: {p}")
                os.remove(p)

            elif os.path.isdir(p):
                logging.info(f"Removing directory: {p}")
                shutil.rmtree(p)
            else:
                logging.critical(f"Unable to remove: {pattern}")


    def clean_results(self):
        paths = self.open_json("cfg/to_clean.json")
        paths = paths["results_paths"]

        self.remove_files(paths)

    def clean_ghidra_repos(self):
        paths = self.open_json("cfg/to_clean.json")
        paths = paths["ghidra_paths"]

        self.remove_files(paths)

    def clean_all(self):
        self.clean_results()
        self.clean_ghidra_repos()

if (__name__ == "__main__"):
    if (len(sys.argv) != 2):
        logging.critical(f"Usage: python {sys.argv[0]} ALL | RESULTS | GHIDRA")
        exit()

    arg = sys.argv[1]

    clean = CLEANUP()

    if (arg == "ALL"):
        clean.clean_all()
    elif (arg == "RESULTS"):
        clean.clean_results()
    elif (arg == "GHIDRA"):
        clean.clean_ghidra_repos()
    else:
        logging.critical(f"Usage: python {sys.argv[0]} ALL | RESULTS | GHIDRA")


