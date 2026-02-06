import argparse
import logging
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from function_match import FUNCTION_MATCH
from sourcegraph_query import SOURCEGRAPH_QUERY


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
    parser.add_argument("--out", required=False)
    parser.add_argument("--token", required=False)
    args = parser.parse_args()

    if args.out:
        os.environ["GSS_OUT"] = args.out
    if args.token:
        os.environ["GSS_TOKEN"] = args.token
    setup_logging(args.out)
    logging.info("Starting Sourcegraph + function match")

    sourcegraph = SOURCEGRAPH_QUERY()
    sourcegraph.iterate_search_strings()

    f = FUNCTION_MATCH()
    f.iterate_through_results()
    logging.info("Analysis complete")


if __name__ == "__main__":
    main()
