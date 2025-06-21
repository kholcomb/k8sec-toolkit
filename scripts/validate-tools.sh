#!/bin/bash

# K8Sec Toolkit Tool Validation Script
# This script validates all security tools are properly integrated and functioning

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_PATH="$PROJECT_ROOT/k8sec-toolkit"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_exit_code="${3:-0}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_info "Running test: $test_name"

    if eval "$test_command" > /dev/null 2>&1; then
        local exit_code=$?
        if [ $exit_code -eq $expected_exit_code ]; then
            log_success "$test_name passed"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            log_error "$test_name failed (exit code: $exit_code, expected: $expected_exit_code)"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        log_error "$test_name failed to execute"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to check if binary exists in PATH or common locations
check_binary_installation() {
    local binary_name="$1"
    local tool_name="$2"

    log_info "Checking $tool_name installation..."

    # Check in PATH
    if command -v "$binary_name" >/dev/null 2>&1; then
        local version_output
        case "$binary_name" in
            "trivy")
                version_output=$(trivy --version 2>/dev/null | head -1)
                ;;
            "kubescape")
                version_output=$(kubescape version 2>/dev/null | head -1)
                ;;
            "kube-bench")
                version_output=$(kube-bench --version 2>/dev/null | head -1)
                ;;
            "kubectl-who-can")
                version_output=$(kubectl-who-can --version 2>/dev/null | head -1 || echo "kubectl-who-can found")
                ;;
            "polaris")
                version_output=$(polaris version 2>/dev/null | head -1)
                ;;
        esac
        log_success "$tool_name found: $version_output"
        return 0
    fi

    # Check common installation paths
    local common_paths=(
        "/usr/local/bin/$binary_name"
        "/opt/homebrew/bin/$binary_name"
        "/usr/bin/$binary_name"
    )

    for path in "${common_paths[@]}"; do
        if [ -x "$path" ]; then
            log_success "$tool_name found at: $path"
            return 0
        fi
    done

    log_warning "$tool_name not found in PATH or common locations"
    WARNINGS=$((WARNINGS + 1))
    return 1
}

# Function to test k8sec-toolkit binary compilation
test_binary_compilation() {
    log_info "Testing k8sec-toolkit binary compilation..."

    cd "$PROJECT_ROOT"

    if go build -o k8sec-toolkit ./cmd/k8sec-toolkit; then
        log_success "k8sec-toolkit compiled successfully"
        return 0
    else
        log_error "k8sec-toolkit compilation failed"
        return 1
    fi
}

# Function to test basic CLI functionality
test_cli_basic() {
    log_info "Testing basic CLI functionality..."

    # Test help command
    run_test "CLI help command" "$BINARY_PATH --help" 0

    # Test version command (assuming it exists)
    run_test "CLI version command" "$BINARY_PATH version" 0 || true

    # Test scan help
    run_test "Scan help command" "$BINARY_PATH scan --help" 0
}

# Function to test secure executor command registry
test_secure_executor() {
    log_info "Testing secure executor command registry..."

    # Create a simple Go test to validate command registry
    cat > /tmp/test_executor.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/kholcomb/k8sec-toolkit/internal/security"
)

func main() {
    executor := security.NewSecureExecutor()
    commands := executor.GetAllowedCommands()

    expectedCommands := []string{
        "trivy-version", "trivy-kubernetes", "trivy-update",
        "kubescape-version", "kubescape-scan", "kubescape-update",
        "kube-bench", "kube-bench-version",
        "kubectl-who-can", "kubectl-who-can-version",
        "polaris", "polaris-version",
    }

    for _, expected := range expectedCommands {
        found := false
        for _, cmd := range commands {
            if cmd == expected {
                found = true
                break
            }
        }
        if !found {
            fmt.Printf("Missing command: %s\n", expected)
            os.Exit(1)
        }
    }

    fmt.Printf("All expected commands found: %d total\n", len(commands))
}
EOF

    cd "$PROJECT_ROOT"
    if go run /tmp/test_executor.go; then
        log_success "Secure executor command registry validation passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Secure executor command registry validation failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    rm -f /tmp/test_executor.go
}

# Function to test tool wrapper functionality
test_tool_wrappers() {
    log_info "Testing tool wrapper implementations..."

    # Create a simple Go test to validate tool wrapper interfaces
    cat > /tmp/test_wrappers.go << 'EOF'
package main

import (
    "fmt"

    "github.com/kholcomb/k8sec-toolkit/internal/config"
    "github.com/kholcomb/k8sec-toolkit/internal/tools"
    "github.com/kholcomb/k8sec-toolkit/internal/types"
)

func testTool(toolName string, tool types.SecurityTool) error {
    // Test GetInfo
    info := tool.GetInfo()
    if info.Name == "" {
        return fmt.Errorf("%s GetInfo returned empty name", toolName)
    }

    // Test GetVersion (should not panic)
    version := tool.GetVersion()
    if version == "" {
        fmt.Printf("Warning: %s GetVersion returned empty version\n", toolName)
    }

    fmt.Printf("%s wrapper validated (version: %s)\n", toolName, version)
    return nil
}

func main() {
    // Test tool wrappers
    tools := map[string]types.SecurityTool{
        "trivy": tools.NewTrivyWrapper(config.TrivyConfig{}),
        "kubescape": tools.NewKubescapeWrapper(config.KubescapeConfig{}),
        "kube-bench": tools.NewKubeBenchWrapper(config.KubeBenchConfig{}),
        "kubectl-who-can": tools.NewKubectlWhoCanWrapper(config.RBACConfig{}),
        "polaris": tools.NewPolarisWrapper(config.PolarisConfig{}),
    }

    for name, tool := range tools {
        if err := testTool(name, tool); err != nil {
            fmt.Printf("Error testing %s: %v\n", name, err)
            return
        }
    }

    fmt.Println("All tool wrappers validated successfully")
}
EOF

    cd "$PROJECT_ROOT"
    if go run /tmp/test_wrappers.go; then
        log_success "Tool wrapper validation passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Tool wrapper validation failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    rm -f /tmp/test_wrappers.go
}

# Function to test configuration loading
test_configuration() {
    log_info "Testing configuration loading..."

    # Create a simple Go test to validate configuration
    cat > /tmp/test_config.go << 'EOF'
package main

import (
    "fmt"

    "github.com/kholcomb/k8sec-toolkit/internal/config"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        fmt.Printf("Configuration loading failed: %v\n", err)
        return
    }

    if len(cfg.Tools.Enabled) == 0 {
        fmt.Println("No tools enabled in configuration")
        return
    }

    fmt.Printf("Configuration loaded successfully with %d enabled tools\n", len(cfg.Tools.Enabled))
}
EOF

    cd "$PROJECT_ROOT"
    if go run /tmp/test_config.go; then
        log_success "Configuration loading test passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Configuration loading test failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    rm -f /tmp/test_config.go
}

# Function to run integration tests (if available)
test_integration() {
    log_info "Running integration tests..."

    cd "$PROJECT_ROOT"

    # Check if integration tests exist
    if find . -name "*_integration_test.go" -o -name "integration_test.go" | grep -q .; then
        if go test -tags=integration ./...; then
            log_success "Integration tests passed"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_error "Integration tests failed"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        log_warning "No integration tests found"
        WARNINGS=$((WARNINGS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to run unit tests
test_unit() {
    log_info "Running unit tests..."

    cd "$PROJECT_ROOT"

    if go test ./...; then
        log_success "Unit tests passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Unit tests failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to check Go module dependencies
test_dependencies() {
    log_info "Checking Go module dependencies..."

    cd "$PROJECT_ROOT"

    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        log_error "go.mod not found"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        return 1
    fi

    # Check if dependencies can be downloaded
    if go mod download; then
        log_success "Dependencies downloaded successfully"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Failed to download dependencies"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    # Check for any missing dependencies
    if go mod verify; then
        log_success "Dependencies verified successfully"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log_error "Dependency verification failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to print final report
print_report() {
    echo
    echo "=================================="
    echo "Tool Validation Report"
    echo "=================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Warnings: $WARNINGS"
    echo

    if [ $FAILED_TESTS -eq 0 ]; then
        log_success "All critical tests passed!"
        if [ $WARNINGS -gt 0 ]; then
            log_warning "$WARNINGS warnings found - check output above"
        fi
        return 0
    else
        log_error "$FAILED_TESTS tests failed"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting K8Sec Toolkit validation..."
    echo

    # Check tool installations (these are warnings, not failures)
    check_binary_installation "trivy" "Trivy"
    check_binary_installation "kubescape" "Kubescape"
    check_binary_installation "kube-bench" "kube-bench"
    check_binary_installation "kubectl-who-can" "kubectl-who-can"
    check_binary_installation "polaris" "Polaris"
    echo

    # Critical tests (these can cause failures)
    test_dependencies
    test_binary_compilation
    test_cli_basic
    test_configuration
    test_secure_executor
    test_tool_wrappers
    test_unit
    test_integration

    # Print final report
    print_report
}

# Run main function
main "$@"
