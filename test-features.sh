#!/bin/bash

# FROST Library Feature Test Runner
# Runs only feature-specific and edge case tests
# Useful for comprehensive testing after critical tests pass

set -e

echo "🎯 Running FROST Library Feature Tests..."
echo "================================================"

# Read tests to run from .testignore (these are the ones we skip in critical)
FEATURE_TESTS=""
if [ -f ".testignore" ]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        if [[ ! "$line" =~ ^[[:space:]]*# ]] && [[ -n "$line" ]]; then
            if [ -z "$FEATURE_TESTS" ]; then
                FEATURE_TESTS="$line"
            else
                FEATURE_TESTS="$FEATURE_TESTS|$line"
            fi
        fi
    done < .testignore
fi

echo "📋 Running feature tests: $FEATURE_TESTS"
echo ""

# Run only the feature tests
if [ -n "$FEATURE_TESTS" ]; then
    echo "🧪 Running feature and edge case tests..."
    go test -v . -run "($FEATURE_TESTS)"
else
    echo "❌ No feature tests found in .testignore"
    exit 1
fi

echo ""
echo "✅ Feature tests completed successfully!"
echo ""
echo "🔍 To run critical tests:"
echo "   ./test-critical.sh"
echo ""
echo "🔍 To run all tests:"
echo "   go test -v ."
