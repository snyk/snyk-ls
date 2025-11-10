#!/bin/bash
# Check for hard-coded URLs that should use constants instead
# This script prevents regression of URL centralization efforts

set -e

# Define the URLs we've centralized as constants
# Using a simple approach with parallel arrays instead of associative arrays
URLS=(
    "https://api.snyk.io"
    "https://app.snyk.io"
    "https://deeproxy.snyk.io"
    "https://api.eu.snyk.io"
    "https://app.eu.snyk.io"
    "https://api.us.snyk.io"
    "https://app.us.snyk.io"
    "https://api.fedramp.snykgov.io"
    "https://app.fedramp.snykgov.io"
    "https://downloads.snyk.io"
    "https://static.snyk.io/snyk-ls"
    "https://github.com/snyk/cli/releases"
    "https://github.com/snyk/snyk-ls/releases"
    "https://api.github.com"
    "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules"
    "https://learn.snyk.io/lesson/license-policy-management/?loc=ide"
    "https://cve.mitre.org/cgi-bin/cvename.cgi"
    "https://cwe.mitre.org/data/definitions"
    "https://snyk.io/vuln"
)

CONSTANTS=(
    "constants.SNYK_API_URL"
    "constants.SNYK_UI_URL"
    "constants.SNYK_DEEPROXY_API_URL"
    "constants.SNYK_API_EU_URL"
    "constants.SNYK_UI_EU_URL"
    "constants.SNYK_API_US_URL"
    "constants.SNYK_UI_US_URL"
    "constants.SNYK_API_FEDRAMP_URL"
    "constants.SNYK_UI_FEDRAMP_URL"
    "constants.SNYK_CLI_DOWNLOAD_BASE_URL"
    "constants.SNYK_LS_DOWNLOAD_BASE_URL"
    "constants.GITHUB_CLI_RELEASES_URL"
    "constants.GITHUB_LS_RELEASES_URL"
    "constants.GITHUB_API_BASE_URL"
    "constants.SNYK_DOCS_CODE_RULES_URL"
    "constants.SNYK_LEARN_LICENSE_URL"
    "constants.CVE_MITRE_BASE_URL"
    "constants.CWE_MITRE_BASE_URL"
    "constants.SNYK_VULN_DB_BASE_URL"
)

# Files to exclude from checks (where hard-coded URLs are intentional)
EXCLUDE_FILES=(
    "internal/constants/urls.go"
    "scripts/check-hardcoded-urls.sh"
    "CHANGELOG.md"
    "README.md"
    "FINAL_SUMMARY.md"
    "TEST_URL_ANALYSIS.md"
    "URL_CENTRALIZATION_SUMMARY.md"
    "main_implementation_plan.md"
)

# Test files where hard-coded URLs for testing URL transformation logic are acceptable
TRANSFORMATION_TEST_FILES=(
    "application/config/config_test.go"
)

ERRORS_FOUND=0

echo "🔍 Checking for hard-coded URLs that should use constants..."
echo ""

# Function to check if a file should be excluded
should_exclude_file() {
    local file=$1
    for exclude in "${EXCLUDE_FILES[@]}"; do
        if [[ "$file" == *"$exclude"* ]]; then
            return 0
        fi
    done
    return 1
}

# Function to check if a file is a transformation test file
is_transformation_test() {
    local file=$1
    for test_file in "${TRANSFORMATION_TEST_FILES[@]}"; do
        if [[ "$file" == *"$test_file"* ]]; then
            return 0
        fi
    done
    return 1
}

# Search for each centralized URL in Go files
for i in "${!URLS[@]}"; do
    url="${URLS[$i]}"
    constant="${CONSTANTS[$i]}"
    
    # Escape special characters for grep
    escaped_url=$(echo "$url" | sed 's/[.[\*^$()+?{|]/\\&/g')
    
    # Find all Go files containing the URL
    while IFS= read -r -d '' file; do
        # Skip excluded files
        if should_exclude_file "$file"; then
            continue
        fi
        
        # For transformation test files, only flag if it's not testing URL transformation
        if is_transformation_test "$file"; then
            # Check if the URL is in a test case that's testing URL transformation
            # Look for context around the URL
            if grep -B 2 -A 2 "$escaped_url" "$file" | grep -q -E "(endpoint|transformation|Custom endpoint|prefix)"; then
                continue
            fi
        fi
        
        # Get line numbers where the URL appears
        line_numbers=$(grep -n "$escaped_url" "$file" | cut -d: -f1)
        
        if [ -n "$line_numbers" ]; then
            echo "❌ Found hard-coded URL in: $file"
            echo "   URL: $url"
            echo "   Should use: $constant"
            echo "   Lines: $line_numbers"
            echo ""
            ERRORS_FOUND=$((ERRORS_FOUND + 1))
        fi
    done < <(find . -name "*.go" -type f -print0)
done

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $ERRORS_FOUND -eq 0 ]; then
    echo "✅ No hard-coded URLs found. All URLs use centralized constants!"
    exit 0
else
    echo "❌ Found $ERRORS_FOUND file(s) with hard-coded URLs"
    echo ""
    echo "Please replace hard-coded URLs with constants from internal/constants/urls.go"
    echo "See URL_CENTRALIZATION_SUMMARY.md for details"
    exit 1
fi
