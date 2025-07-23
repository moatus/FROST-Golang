#!/bin/bash

# FROST Library Critical Test Runner
# Runs only security-critical and core functionality tests
# Skips feature-specific and edge case tests for faster CI

set -e

echo "🔒 Running FROST Library Critical Tests..."
echo "================================================"

# Build list of critical tests (tests NOT in .testignore)
CRITICAL_TESTS=""
if [ -f ".testignore" ]; then
    # Get all test functions
    ALL_TESTS=$(go test -list . 2>/dev/null | grep "^Test" || echo "")

    if [ -n "$ALL_TESTS" ]; then
        # Read tests to skip from .testignore
        SKIP_TESTS=""
        while IFS= read -r line; do
            # Skip comments and empty lines
            if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*$ ]]; then
                if [ -z "$SKIP_TESTS" ]; then
                    SKIP_TESTS="$line"
                else
                    SKIP_TESTS="$SKIP_TESTS|$line"
                fi
            fi
        done < .testignore

        # Build critical tests list (exclude tests in .testignore)
        for test in $ALL_TESTS; do
            if [[ ! "$test" =~ ^($SKIP_TESTS)$ ]]; then
                if [ -z "$CRITICAL_TESTS" ]; then
                    CRITICAL_TESTS="$test"
                else
                    CRITICAL_TESTS="$CRITICAL_TESTS|$test"
                fi
            fi
        done
    fi
fi

# Run critical tests
if [ -n "$CRITICAL_TESTS" ]; then
    echo "📋 Running critical tests: $CRITICAL_TESTS"
    echo ""
    echo "🧪 Running critical tests (excluding feature/edge cases)..."
    go test -v . -run "^($CRITICAL_TESTS)$"
else
    echo "🧪 Running all tests (no .testignore found or no tests filtered)..."
    go test -v .
fi

echo ""
echo "✅ Critical tests completed successfully!"
echo ""
echo "🔍 To run feature tests separately:"
echo "   go test -v . -run \"($SKIP_TESTS)\""
echo ""
echo "🔍 To run all tests:"
echo "   go test -v ."
