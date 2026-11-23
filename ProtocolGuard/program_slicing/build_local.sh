#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build/src
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
CLANGXX=${CLANGXX:-clang++-18}
for name in AnalyzerPass MatchPass AssertPass; do
  "$CLANGXX" $("$LLVM_CONFIG" --cxxflags) -std=c++17 -fPIC -shared src/Passes.cpp -o "build/src/lib${name}.so" $("$LLVM_CONFIG" --ldflags --libs core passes analysis support) $("$LLVM_CONFIG" --system-libs)
done
