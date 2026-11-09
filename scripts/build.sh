#!/usr/bin/env bash

set -euo pipefail

# Default values
PRESET="debug"
CLEAN=false
CLEAN_ONLY=false
RUN_TESTS=false

show_usage() {
    echo "Usage: $0 [debug|release|sanitize] [clean] [clean-only] [test]"
    echo ""
    echo "Options:"
    echo "  debug        Build with Debug configuration (default)"
    echo "  release      Build with Release configuration (optimized)"
    echo "  sanitize     Build with AddressSanitizer and UndefinedBehaviorSanitizer"
    echo "  clean        Clean build artifacts before building"
    echo "  clean-only   Clean build artifacts and exit"
    echo "  test, check  Run test suite via CTest after building"
    echo "  -h, --help   Show this help message"
}

# Parse arguments
for arg in "$@"; do
    # Convert argument to lowercase for easier matching
    case "${arg,,}" in
        debug|--debug)
            PRESET="debug"
            ;;
        release|--release)
            PRESET="release"
            ;;
        sanitize|--sanitize|asan|ubsan)
            PRESET="sanitize"
            ;;
        clean|--clean)
            CLEAN=true
            ;;
        clean-only|--clean-only)
            CLEAN=true
            CLEAN_ONLY=true
            ;;
        test|check|--test|--check)
            RUN_TESTS=true
            ;;
        -h|--help|help)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$arg'" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

# Navigate to the project root directory (where the script's parent folder is)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

if [ "$CLEAN" = true ]; then
    echo "Cleaning build artifacts..."
    if [ -d "build" ]; then
        if command -v trash &> /dev/null; then
            trash build
        else
            rm -rf build
        fi
    fi
    if [ -L "compile_commands.json" ] || [ -f "compile_commands.json" ]; then
        if command -v trash &> /dev/null; then
            trash compile_commands.json
        else
            rm -f compile_commands.json
        fi
    fi
    if [ "$CLEAN_ONLY" = true ]; then
        echo "Clean completed."
        exit 0
    fi
fi

echo "=== Building urtp ($PRESET) ==="

# Configure CMake using presets
cmake --preset "$PRESET"

# Build the project in parallel
cmake --build --preset "$PRESET" --parallel

# Expose compile_commands.json in build/ and root for tooling
if [ -f "build/${PRESET}/compile_commands.json" ]; then
    ln -sf "${PRESET}/compile_commands.json" "build/compile_commands.json"
    ln -sf "build/${PRESET}/compile_commands.json" "compile_commands.json"
fi

if [ "$RUN_TESTS" = true ]; then
    echo "=== Running Unity Tests via CTest ($PRESET) ==="
    ctest --preset "test-$PRESET"
fi
