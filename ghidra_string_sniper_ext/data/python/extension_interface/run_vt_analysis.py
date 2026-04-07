import argparse
import logging
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0,str(ROOT))

from analyze_vt import ANALYZE_VT

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--jsonpath",required=True)

  args = parser.parse_args()

  analyzer = ANALYZE_VT()
  
  return analyzer.analyze(args.jsonpath)

if __name__ == "__main__":
  main()
