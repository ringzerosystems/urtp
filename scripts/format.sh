#!/bin/bash
find . -type d \( -name "vendored" -o -name "build" -o -name ".cache" \) -prune -o -type f \( -name "*.c" -o -name "*.h" \) -print | xargs --no-run-if-empty clang-format -i
