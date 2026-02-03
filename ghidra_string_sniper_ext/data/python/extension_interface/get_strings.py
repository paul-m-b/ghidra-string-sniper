import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from string_prioritize import STRING_PRIORITIZE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=False)
    parser.add_argument("--token", required=False)
    parser.add_argument("--language", required=False)
    args = parser.parse_args()

    if args.out:
        os.environ["GSS_OUT"] = args.out
    if args.token:
        os.environ["GSS_TOKEN"] = args.token

    BINARY_PATH = args.binary
    LANGUAGE = args.language

    s = STRING_PRIORITIZE()
    s.prioritize_strings(BINARY_PATH, lang=LANGUAGE)

    print("Done...")


if __name__ == "__main__":
    main()
