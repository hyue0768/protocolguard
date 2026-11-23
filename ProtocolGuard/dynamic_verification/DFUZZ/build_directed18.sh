#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build18
clang++-18 $(llvm-config-18 --cxxflags) -std=c++17 -fPIC -shared Directed18.cpp -o build18/libDirected18.so $(llvm-config-18 --ldflags --libs core passes analysis support) $(llvm-config-18 --system-libs)
