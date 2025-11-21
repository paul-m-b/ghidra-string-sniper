from string_prioritize import STRING_PRIORITIZE
import sys

def main():
    BINARY_PATH = sys.argv[1]
    LANGUAGE = None

    s = STRING_PRIORITIZE()
    s.prioritize_strings(BINARY_PATH, lang=LANGUAGE)

    print("Done...")

if (__name__ == "__main__"):
    main()
