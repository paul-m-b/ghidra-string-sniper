import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from function_match import FUNCTION_MATCH
from sourcegraph_query import SOURCEGRAPH_QUERY


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=False)
    parser.add_argument("--token", required=False)
    args = parser.parse_args()

    if args.out:
        os.environ["GSS_OUT"] = args.out
    if args.token:
        os.environ["GSS_TOKEN"] = args.token

    sourcegraph = SOURCEGRAPH_QUERY()
    sourcegraph.iterate_search_strings()

    f = FUNCTION_MATCH()
    f.iterate_through_results()


if __name__ == "__main__":
    main()
