import argparse
import json
import logging
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from string_prioritize import STRING_PRIORITIZE


def setup_logging(out_dir: str) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    if out_dir:
        log_path = Path(out_dir) / "pipeline.log"
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--strings", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--token", required=False)
    parser.add_argument("--model", required=False)
    parser.add_argument("--max-strings", type=int, required=False)
    args = parser.parse_args()

    os.environ["GSS_OUT"] = args.out
    if args.token:
        os.environ["GSS_TOKEN"] = args.token
    setup_logging(args.out)
    logging.info("Ranking strings from %s", args.strings)

    with open(args.strings, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    strings = [entry.get("value", "") for entry in data.get("strings", [])]
    logging.info("Loaded %d strings", len(strings))

    s = STRING_PRIORITIZE()
    if args.model:
        s.MODEL = args.model
    if args.max_strings is not None:
        s.MAX_STRING_COUNT = args.max_strings

    logging.info("Starting prioritization")
    s.prioritize_strings_list(strings)
    logging.info("Prioritization complete")


if __name__ == "__main__":
    main()
