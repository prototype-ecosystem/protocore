#!/bin/bash
# scripts/reproducible-build.sh
# Reproducible build script for Proto Core blockchain node
# Ensures deterministic builds across different machines

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION=${1:-"1.0.0"}
RUST_VERSION="1.75.0"
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_BINARY="target/release/protocore"
MANIFEST_FILE="build-manifest.json"

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if rustup is installed
    if ! command -v rustup &> /dev/null; then
        log_error "rustup is not installed. Please install it from https://rustup.rs"
        exit 1
    fi

    # Check if cargo is installed
    if ! command -v cargo &> /dev/null; then
        log_error "cargo is not installed. Please install Rust toolchain."
        exit 1
    fi

    # Check if git is installed
    if ! command -v git &> /dev/null; then
        log_error "git is not installed. Please install git."
        exit 1
    fi

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_warn "Not in a git repository. Commit hash will be set to 'unknown'."
    fi

    # Check if Cargo.lock exists
    if [[ ! -f "${BUILD_DIR}/Cargo.lock" ]]; then
        log_error "Cargo.lock not found. Run 'cargo generate-lockfile' first."
        exit 1
    fi

    log_success "All prerequisites met."
}

# Function to get the current git commit
get_commit_hash() {
    if git rev-parse --git-dir > /dev/null 2>&1; then
        git rev-parse HEAD
    else
        echo "unknown"
    fi
}

# Function to get git dirty status
get_git_status() {
    if git rev-parse --git-dir > /dev/null 2>&1; then
        if [[ -n $(git status --porcelain) ]]; then
            echo "dirty"
        else
            echo "clean"
        fi
    else
        echo "unknown"
    fi
}

# Function to compute sha256 hash (cross-platform)
compute_sha256() {
    local file="$1"
    if command -v sha256sum &> /dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        log_error "No sha256 tool found. Install coreutils or use macOS shasum."
        exit 1
    fi
}

# Function to setup reproducible build environment
setup_build_environment() {
    log_info "Setting up reproducible build environment..."

    # Install and set the specific Rust version
    log_info "Installing Rust ${RUST_VERSION}..."
    rustup install "${RUST_VERSION}" --profile minimal || true
    rustup override set "${RUST_VERSION}"

    # Verify Rust version
    CURRENT_RUST=$(rustc --version)
    log_info "Using Rust: ${CURRENT_RUST}"

    # Set reproducible build environment variables
    export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || date +%s)
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="-C debuginfo=0 -C strip=symbols"

    # Disable features that could introduce non-determinism
    export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}

    log_success "Build environment configured."
}

# Function to clean previous builds
clean_build() {
    log_info "Cleaning previous builds..."
    cd "${BUILD_DIR}"
    cargo clean
    rm -f "${MANIFEST_FILE}"
    log_success "Build directory cleaned."
}

# Function to perform the build
perform_build() {
    log_info "Starting reproducible build..."
    cd "${BUILD_DIR}"

    # Build with locked dependencies for reproducibility
    RUSTFLAGS="${RUSTFLAGS:-}" cargo build \
        --release \
        --locked \
        --target-dir target \
        2>&1 | tee build.log

    # Verify the binary was created
    if [[ ! -f "${TARGET_BINARY}" ]]; then
        log_error "Build failed: ${TARGET_BINARY} not found"
        exit 1
    fi

    log_success "Build completed successfully."
}

# Function to generate build manifest
generate_manifest() {
    log_info "Generating build manifest..."

    local commit=$(get_commit_hash)
    local git_status=$(get_git_status)
    local rust_version=$(rustc --version)
    local cargo_version=$(cargo --version)
    local build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local binary_hash=$(compute_sha256 "${TARGET_BINARY}")
    local cargo_lock_hash=$(compute_sha256 "Cargo.lock")
    local binary_size=$(stat -f%z "${TARGET_BINARY}" 2>/dev/null || stat -c%s "${TARGET_BINARY}" 2>/dev/null)
    local os_info=$(uname -s)
    local arch_info=$(uname -m)

    # Get dependency count
    local dep_count=$(cargo metadata --format-version 1 --locked 2>/dev/null | jq '.packages | length' 2>/dev/null || echo "unknown")

    cat > "${MANIFEST_FILE}" << EOF
{
    "version": "${VERSION}",
    "commit": "${commit}",
    "git_status": "${git_status}",
    "rust_version": "${rust_version}",
    "cargo_version": "${cargo_version}",
    "build_time": "${build_time}",
    "build_os": "${os_info}",
    "build_arch": "${arch_info}",
    "binary_hash": "${binary_hash}",
    "binary_size": ${binary_size},
    "cargo_lock_hash": "${cargo_lock_hash}",
    "dependency_count": "${dep_count}",
    "reproducible_build": true,
    "build_flags": {
        "incremental": false,
        "debuginfo": 0,
        "strip": "symbols",
        "locked": true
    }
}
EOF

    log_success "Build manifest generated: ${MANIFEST_FILE}"
}

# Function to verify build reproducibility
verify_reproducibility() {
    log_info "Verifying build reproducibility..."

    local first_hash=$(compute_sha256 "${TARGET_BINARY}")

    # Rebuild to verify determinism
    log_info "Performing verification rebuild..."
    cargo clean
    perform_build

    local second_hash=$(compute_sha256 "${TARGET_BINARY}")

    if [[ "${first_hash}" == "${second_hash}" ]]; then
        log_success "Build is reproducible! Hash: ${first_hash}"
        return 0
    else
        log_error "Build is NOT reproducible!"
        log_error "First build:  ${first_hash}"
        log_error "Second build: ${second_hash}"
        return 1
    fi
}

# Function to display build summary
display_summary() {
    echo ""
    echo "=============================================="
    echo "       Proto Core Build Summary"
    echo "=============================================="
    echo ""
    cat "${MANIFEST_FILE}" | jq '.' 2>/dev/null || cat "${MANIFEST_FILE}"
    echo ""
    echo "=============================================="
    echo ""
    log_success "Build artifacts:"
    echo "  - Binary: ${BUILD_DIR}/${TARGET_BINARY}"
    echo "  - Manifest: ${BUILD_DIR}/${MANIFEST_FILE}"
    echo "  - Build log: ${BUILD_DIR}/build.log"
    echo ""
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [VERSION]

Reproducible build script for Proto Core blockchain node.

Arguments:
    VERSION     Version string for the build (default: 1.0.0)

Options:
    -h, --help      Show this help message
    -c, --clean     Clean build only (no rebuild)
    -v, --verify    Verify build reproducibility (builds twice)
    --skip-clean    Skip the clean step

Examples:
    $(basename "$0")              # Build with default version
    $(basename "$0") 2.0.0        # Build version 2.0.0
    $(basename "$0") -v 1.5.0     # Build and verify reproducibility

EOF
}

# Main function
main() {
    local do_verify=false
    local skip_clean=false
    local clean_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verify)
                do_verify=true
                shift
                ;;
            -c|--clean)
                clean_only=true
                shift
                ;;
            --skip-clean)
                skip_clean=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                VERSION="$1"
                shift
                ;;
        esac
    done

    COMMIT=$(get_commit_hash)

    echo ""
    log_info "=========================================="
    log_info "  Building Proto Core v${VERSION}"
    log_info "  Commit: ${COMMIT}"
    log_info "=========================================="
    echo ""

    cd "${BUILD_DIR}"

    check_prerequisites
    setup_build_environment

    if [[ "${clean_only}" == true ]]; then
        clean_build
        log_success "Clean complete."
        exit 0
    fi

    if [[ "${skip_clean}" != true ]]; then
        clean_build
    fi

    perform_build
    generate_manifest

    if [[ "${do_verify}" == true ]]; then
        verify_reproducibility
    fi

    display_summary

    log_success "Proto Core v${VERSION} build complete!"
}

# Run main function
main "$@"
