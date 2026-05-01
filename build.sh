#!/usr/bin/env bash
# Heimdall IDS — Frontend build script
# Compiles all skin JSX → plain JS using esbuild.
# Run after any change to a skin's app.jsx.
#
# Requirements: esbuild  (npm install -g esbuild)
set -euo pipefail

ESBUILD="${ESBUILD:-esbuild}"
FLAGS="--minify --jsx-factory=React.createElement --jsx-fragment=React.Fragment"

compile() {
  local skin=$1
  local src="frontend/skins/${skin}/app.jsx"
  local out="frontend/skins/${skin}/app.js"
  printf "  %-12s " "$skin"
  $ESBUILD "$src" $FLAGS --outfile="$out"
  printf "%s KB\n" "$(du -k "$out" | cut -f1)"
}

echo "Building Heimdall skins..."
compile original
compile chronicles
compile mosaic
compile seal
echo "Done."
