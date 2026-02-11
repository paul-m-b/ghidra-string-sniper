# Ghidra String Sniper

Reverse engineering proprietary software comes with many challenges. Often, binaries are stripped and lack symbols. This means getting started with the reversing process can often be challenging and it may lead to a situation where lots of time is spent reversing functions/libraries/etc. that are open source and readily available. Or, in the worst case, guesswork is utilized and functions, structures, and symbols are never accurately resolved. Sourcegraph.com is a tool that essentially provides a fast way to search github repositories en masse. This comes in handy in the reversing process particularly with strings found in binaries. In my experience, even if symbols are stripped, there are still useful strings that can point to what the program is doing/using. From a search of these strings, you may be able to find implementations/uses of the library in question. If it looks like your binary is utilizing something similar, you can then easily transfer the header files, symbols, structures (whatever is useful) to your binary. In an ideal situation, this could save copious amounts of time when starting to reverse a binary and get a better “bigger picture” understanding of what you’re looking at. For example, imagine a binary is using the Raknet networking protocol. You could search for Raknet on sourcegraph, stumble upon this file: https://sourcegraph.com/github.com/WAReborn/WorldsAdriftReborn/-/blob/WorldsAdriftRebornC oreSdk/Structs.h?L261:8-261:24 and potentially extract useful information from it. This is a rough example, but it should help you get the idea. The ultimate goal would be to integrate this entire process into a Ghidra extension. It would do the following steps: 1. Identify useful/unique strings in the binary. 2. Search sourcegraph for related functions. 3. Utilize an LLM to find matches between the sourcegraph output and the assembly/decompilation of the binary. 4. Provide a list to the reverse engineer of potential matches that can then be either manually, or maybe even automatically, applied to the binary.

## Introduction / Proposal

Reverse engineering proprietary software comes with many challenges. Often, binaries are stripped and lack symbols. This means getting started with the reversing process can often be challenging and it may lead to a situation where lots of time is spent reversing functions/libraries/etc. that are open source and readily available. Or, in the worst case, guesswork is utilized and functions, structures, and symbols are never accurately resolved. 

Sourcegraph.com is a tool that essentially provides a fast way to search github repositories en masse. This comes in handy in the reversing process particularly with strings found in binaries. In my experience, even if symbols are stripped, there are still useful strings that can point to what the program is doing/using. From a search of these strings, you may be able to find implementations/uses of the library in question. If it looks like your binary is utilizing something similar, you can then easily transfer the header files, symbols, structures (whatever is useful) to your binary. 

In an ideal situation, this could save copious amounts of time when starting to reverse a binary and get a better “bigger picture” understanding of what you’re looking at. The ultimate goal would be to integrate this entire process into a Ghidra extension. 

It would do the following steps:

1. Identify useful/unique strings in the binary.
2. Search sourcegraph for related functions.
3. Utilize an LLM to find matches between the sourcegraph output and the assembly/decompilation of the binary.
4. Provide a list to the reverse engineer of potential matches that can then be either manually, or maybe even automatically, applied to the binary.

## Status

Ghidra String Sniper is in active development. The Python backend is sufficient as a PoC. The Ghidra Extension is in development.

## Documentation
Docs here: `docs/README.md`

## License

MIT License
