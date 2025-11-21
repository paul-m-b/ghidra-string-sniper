from function_match import FUNCTION_MATCH
from sourcegraph_query import SOURCEGRAPH_QUERY

def main():
    sourcegraph = SOURCEGRAPH_QUERY()
    sourcegraph.iterate_search_strings()

    f = FUNCTION_MATCH()
    f.iterate_through_results()

if (__name__ == "__main__"):
    main()
