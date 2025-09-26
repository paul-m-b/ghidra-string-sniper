#!/bin/sh

rm -rf dist/
gradle -PGHIDRA_INSTALL_DIR=/usr/local/bin/ghidraFiles
rm -rf "$HOME/.config/ghidra/ghidra_11.4.2_PUBLIC/Extensions/ghidra_string_sniper_ext/"
for file in "dist/*"; do
	unzip -o $file -d "$HOME/.config/ghidra/ghidra_11.4.2_PUBLIC/Extensions/"
done
