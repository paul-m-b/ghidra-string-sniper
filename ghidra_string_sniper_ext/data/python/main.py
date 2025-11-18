from string_prioritize import STRING_PRIORITIZE
from function_match import FUNCTION_MATCH
from sourcegraph_query import SOURCEGRAPH_QUERY

def main():
    BINARY_PATH = "./server"
    LANGUAGE = None

    s = STRING_PRIORITIZE()
    s.prioritize_strings(BINARY_PATH, lang=LANGUAGE)

    sourcegraph = SOURCEGRAPH_QUERY()
    sourcegraph.iterate_search_strings()

    f = FUNCTION_MATCH()
    f.iterate_through_results()

    print("Done...")


if (__name__ == "__main__"):
    main()
