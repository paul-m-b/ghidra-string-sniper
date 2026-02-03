import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from string_prioritize import STRING_PRIORITIZE
from sourcegraph_query import SOURCEGRAPH_QUERY
from function_match import FUNCTION_MATCH


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--token", required=False)
    parser.add_argument("--language", required=False)
    parser.add_argument("--model", required=False)
    parser.add_argument("--max-strings", type=int, required=False)
    args = parser.parse_args()

    os.environ["GSS_OUT"] = args.out
    if args.token:
        os.environ["GSS_TOKEN"] = args.token
    if "PYGHIDRA_PROJECT_DIR" not in os.environ:
        os.environ["PYGHIDRA_PROJECT_DIR"] = args.out

    s = STRING_PRIORITIZE()
    if args.model:
        s.MODEL = args.model
    if args.max_strings is not None:
        s.MAX_STRING_COUNT = args.max_strings

    s.prioritize_strings(args.binary, lang=args.language)

    sourcegraph = SOURCEGRAPH_QUERY()
    sourcegraph.iterate_search_strings()

    f = FUNCTION_MATCH()
    f.iterate_through_results()

    print("Done...")


if __name__ == "__main__":
    main()
