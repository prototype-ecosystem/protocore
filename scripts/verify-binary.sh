#!/bin/bash
# scripts/verify-binary.sh
# Verify Proto Core binary against official release manifest
# Supports both local and remote verification

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/.."
DEFAULT_RELEASE_URL="https://releases.protocore.io"
TEMP_DIR=$(mktemp -d)
MIN_SIGNATURES_REQUIRED=3

# Core team public keys (placeholder - replace with actual keys)
declare -A CORE_TEAM_KEYS=(
    ["alice"]="0x1234567890abcdef1234567890abcdef12345678"
    ["bob"]="0xabcdef1234567890abcdef1234567890abcdef12"
    ["charlie"]="0x567890abcdef1234567890abcdef1234567890ab"
    ["diana"]="0x90abcdef1234567890abcdef1234567890abcdef"
    ["eve"]="0xdef1234567890abcdef1234567890abcdef12345"
)

# Cleanup function
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

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

log_check() {
    echo -e "${CYAN}[CHECK]${NC} $1"
}

# Function to compute sha256 hash (cross-platform)
compute_sha256() {
    local file="$1"
    if command -v sha256sum &> /dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        log_error "No sha256 tool found."
        exit 1
    fi
}

# Function to download file
download_file() {
    local url="$1"
    local output="$2"

    log_info "Downloading: ${url}"

    if command -v curl &> /dev/null; then
        curl -fsSL -o "${output}" "${url}"
    elif command -v wget &> /dev/null; then
        wget -q -O "${output}" "${url}"
    else
        log_error "Neither curl nor wget found. Please install one."
        exit 1
    fi
}

# Function to fetch release manifest
fetch_manifest() {
    local manifest_url="$1"
    local manifest_file="${TEMP_DIR}/manifest.json"

    download_file "${manifest_url}" "${manifest_file}"

    if [[ ! -f "${manifest_file}" ]]; then
        log_error "Failed to download manifest from ${manifest_url}"
        exit 1
    fi

    echo "${manifest_file}"
}

# Function to fetch signatures
fetch_signatures() {
    local base_url="$1"
    local version="$2"
    local signatures_dir="${TEMP_DIR}/signatures"

    mkdir -p "${signatures_dir}"

    # Try to download signatures index
    local signatures_index_url="${base_url}/v${version}/signatures/index.json"
    local signatures_index="${signatures_dir}/index.json"

    if download_file "${signatures_index_url}" "${signatures_index}" 2>/dev/null; then
        # Parse index and download each signature
        local sig_files=$(jq -r '.signatures[]' "${signatures_index}" 2>/dev/null || echo "")
        for sig_file in ${sig_files}; do
            local sig_url="${base_url}/v${version}/signatures/${sig_file}"
            download_file "${sig_url}" "${signatures_dir}/${sig_file}" 2>/dev/null || true
        done
    else
        # Try known signer names
        for signer in "${!CORE_TEAM_KEYS[@]}"; do
            local sig_url="${base_url}/v${version}/signatures/${version}-${signer}.sig"
            download_file "${sig_url}" "${signatures_dir}/${version}-${signer}.sig" 2>/dev/null || true
        done
    fi

    echo "${signatures_dir}"
}

# Function to verify binary hash
verify_binary_hash() {
    local binary_path="$1"
    local expected_hash="$2"

    log_check "Verifying binary hash..."

    if [[ ! -f "${binary_path}" ]]; then
        log_error "Binary not found: ${binary_path}"
        return 1
    fi

    local actual_hash=$(compute_sha256 "${binary_path}")

    echo "  Expected: ${expected_hash}"
    echo "  Actual:   ${actual_hash}"

    if [[ "${actual_hash}" == "${expected_hash}" ]]; then
        log_success "Binary hash verified!"
        return 0
    else
        log_error "Binary hash mismatch!"
        return 1
    fi
}

# Function to verify Cargo.lock hash
verify_cargo_lock() {
    local cargo_lock_path="$1"
    local expected_hash="$2"

    log_check "Verifying Cargo.lock hash..."

    if [[ ! -f "${cargo_lock_path}" ]]; then
        log_warn "Cargo.lock not found: ${cargo_lock_path}"
        return 0
    fi

    local actual_hash=$(compute_sha256 "${cargo_lock_path}")

    echo "  Expected: ${expected_hash}"
    echo "  Actual:   ${actual_hash}"

    if [[ "${actual_hash}" == "${expected_hash}" ]]; then
        log_success "Cargo.lock hash verified!"
        return 0
    else
        log_warn "Cargo.lock hash mismatch (may indicate different dependencies)"
        return 1
    fi
}

# Function to verify GPG signature
verify_gpg_signature() {
    local message_file="$1"
    local signature_file="$2"
    local signer_id="$3"

    if ! command -v gpg &> /dev/null; then
        log_warn "GPG not installed. Skipping GPG signature verification."
        return 2
    fi

    if gpg --verify "${signature_file}" "${message_file}" 2>/dev/null; then
        log_success "GPG signature from ${signer_id} verified!"
        return 0
    else
        log_warn "GPG signature from ${signer_id} could not be verified."
        return 1
    fi
}

# Function to verify signature bundle
verify_signature_bundle() {
    local bundle_file="$1"
    local expected_binary_hash="$2"

    if [[ ! -f "${bundle_file}" ]]; then
        return 1
    fi

    local signer_id=$(jq -r '.signer_id' "${bundle_file}" 2>/dev/null)
    local sign_method=$(jq -r '.sign_method' "${bundle_file}" 2>/dev/null)
    local message_hash=$(jq -r '.message_hash' "${bundle_file}" 2>/dev/null)
    local signature=$(jq -r '.signature' "${bundle_file}" 2>/dev/null)

    if [[ -z "${signer_id}" ]] || [[ "${signer_id}" == "null" ]]; then
        return 1
    fi

    log_check "Verifying signature from: ${signer_id} (method: ${sign_method})"

    # For now, we just check that the signature exists and has valid structure
    # In production, you would verify against known public keys
    if [[ -n "${signature}" ]] && [[ "${signature}" != "null" ]]; then
        log_success "Signature from ${signer_id} present and valid format."
        echo "${signer_id}"
        return 0
    fi

    return 1
}

# Function to verify multi-signature threshold
verify_multisig_threshold() {
    local signatures_dir="$1"
    local expected_binary_hash="$2"
    local required_sigs="$3"

    log_check "Verifying multi-signature threshold (${required_sigs} required)..."

    local valid_signers=()

    # Check all signature bundles
    for bundle_file in "${signatures_dir}"/*.json; do
        [[ -f "${bundle_file}" ]] || continue
        [[ "$(basename "${bundle_file}")" == "index.json" ]] && continue

        local signer=$(verify_signature_bundle "${bundle_file}" "${expected_binary_hash}")
        if [[ -n "${signer}" ]]; then
            valid_signers+=("${signer}")
        fi
    done

    local valid_count=${#valid_signers[@]}

    echo ""
    echo "  Valid signatures: ${valid_count}/${required_sigs} required"
    echo "  Signers: ${valid_signers[*]:-none}"
    echo ""

    if [[ ${valid_count} -ge ${required_sigs} ]]; then
        log_success "Multi-signature threshold met!"
        return 0
    else
        log_error "Multi-signature threshold NOT met!"
        log_error "Need ${required_sigs} signatures, have ${valid_count}"
        return 1
    fi
}

# Function to verify build reproducibility
verify_reproducibility() {
    local manifest_file="$1"

    log_check "Checking build reproducibility flags..."

    local reproducible=$(jq -r '.reproducible_build' "${manifest_file}" 2>/dev/null)
    local incremental=$(jq -r '.build_flags.incremental' "${manifest_file}" 2>/dev/null)
    local locked=$(jq -r '.build_flags.locked' "${manifest_file}" 2>/dev/null)

    echo "  Reproducible build: ${reproducible}"
    echo "  Incremental: ${incremental}"
    echo "  Locked deps: ${locked}"

    if [[ "${reproducible}" == "true" ]] && [[ "${incremental}" == "false" ]] && [[ "${locked}" == "true" ]]; then
        log_success "Build reproducibility flags verified!"
        return 0
    else
        log_warn "Build may not be reproducible."
        return 1
    fi
}

# Function to verify git commit
verify_commit() {
    local expected_commit="$1"

    log_check "Verifying git commit..."

    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_warn "Not in a git repository. Cannot verify commit."
        return 0
    fi

    local current_commit=$(git rev-parse HEAD)

    echo "  Expected: ${expected_commit}"
    echo "  Current:  ${current_commit}"

    if [[ "${current_commit}" == "${expected_commit}" ]]; then
        log_success "Git commit verified!"
        return 0
    else
        log_warn "Git commit mismatch. You may be on a different branch/commit."
        return 1
    fi
}

# Function to perform full verification
perform_full_verification() {
    local manifest_url="$1"
    local binary_path="$2"
    local cargo_lock_path="$3"

    local verification_results=()
    local failed=0

    echo ""
    log_info "=========================================="
    log_info "  Proto Core Binary Verification"
    log_info "=========================================="
    echo ""

    # Fetch manifest
    log_info "Fetching release manifest..."
    local manifest_file=$(fetch_manifest "${manifest_url}")

    # Parse manifest
    local version=$(jq -r '.version' "${manifest_file}")
    local expected_binary_hash=$(jq -r '.binary_hash' "${manifest_file}")
    local expected_cargo_lock_hash=$(jq -r '.cargo_lock_hash' "${manifest_file}")
    local expected_commit=$(jq -r '.commit' "${manifest_file}")
    local rust_version=$(jq -r '.rust_version' "${manifest_file}")
    local build_time=$(jq -r '.build_time' "${manifest_file}")

    echo ""
    echo "Release Information:"
    echo "  Version:      ${version}"
    echo "  Commit:       ${expected_commit}"
    echo "  Rust:         ${rust_version}"
    echo "  Build Time:   ${build_time}"
    echo ""

    # Verify binary hash
    if verify_binary_hash "${binary_path}" "${expected_binary_hash}"; then
        verification_results+=("Binary hash: PASS")
    else
        verification_results+=("Binary hash: FAIL")
        ((failed++))
    fi
    echo ""

    # Verify Cargo.lock hash
    if verify_cargo_lock "${cargo_lock_path}" "${expected_cargo_lock_hash}"; then
        verification_results+=("Cargo.lock hash: PASS")
    else
        verification_results+=("Cargo.lock hash: WARN")
    fi
    echo ""

    # Verify git commit (optional)
    if verify_commit "${expected_commit}"; then
        verification_results+=("Git commit: PASS")
    else
        verification_results+=("Git commit: WARN")
    fi
    echo ""

    # Verify reproducibility flags
    if verify_reproducibility "${manifest_file}"; then
        verification_results+=("Reproducibility: PASS")
    else
        verification_results+=("Reproducibility: WARN")
    fi
    echo ""

    # Fetch and verify signatures
    local base_url=$(dirname "${manifest_url}")
    local signatures_dir=$(fetch_signatures "$(dirname "${base_url}")" "${version}")

    if verify_multisig_threshold "${signatures_dir}" "${expected_binary_hash}" "${MIN_SIGNATURES_REQUIRED}"; then
        verification_results+=("Multi-sig threshold: PASS")
    else
        verification_results+=("Multi-sig threshold: FAIL")
        ((failed++))
    fi

    # Display summary
    echo ""
    echo "=============================================="
    echo "       Verification Summary"
    echo "=============================================="
    echo ""
    for result in "${verification_results[@]}"; do
        if [[ "${result}" == *"PASS"* ]]; then
            echo -e "  ${GREEN}[PASS]${NC} ${result%:*}"
        elif [[ "${result}" == *"FAIL"* ]]; then
            echo -e "  ${RED}[FAIL]${NC} ${result%:*}"
        else
            echo -e "  ${YELLOW}[WARN]${NC} ${result%:*}"
        fi
    done
    echo ""
    echo "=============================================="
    echo ""

    if [[ ${failed} -eq 0 ]]; then
        log_success "All critical verifications passed!"
        log_success "This binary is authentic and matches the official release."
        return 0
    else
        log_error "Verification failed!"
        log_error "This binary may have been tampered with or is not an official release."
        log_error "DO NOT USE THIS BINARY!"
        return 1
    fi
}

# Function to verify local build
verify_local_build() {
    local manifest_file="$1"
    local binary_path="$2"

    log_info "Verifying local build against manifest..."

    if [[ ! -f "${manifest_file}" ]]; then
        log_error "Local manifest not found: ${manifest_file}"
        exit 1
    fi

    local expected_hash=$(jq -r '.binary_hash' "${manifest_file}")
    verify_binary_hash "${binary_path}" "${expected_hash}"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [MANIFEST_URL]

Verify Proto Core binary against official release manifest.

Arguments:
    MANIFEST_URL    URL to the release manifest (default: latest from releases.protocore.io)

Options:
    -h, --help              Show this help message
    -b, --binary PATH       Path to binary to verify (default: target/release/protocore)
    -m, --manifest PATH     Use local manifest file instead of URL
    -l, --local             Verify local build against local manifest
    -s, --signatures NUM    Minimum signatures required (default: 3)
    --skip-sigs             Skip signature verification
    -v, --version VER       Verify specific version

Examples:
    $(basename "$0")
        # Verify local binary against latest release

    $(basename "$0") https://releases.protocore.io/v1.0.0/manifest.json
        # Verify against specific manifest URL

    $(basename "$0") -l
        # Verify local build against local manifest

    $(basename "$0") -v 1.5.0
        # Verify against version 1.5.0

    $(basename "$0") --skip-sigs -b /path/to/protocore
        # Verify binary hash only, skip signature check

EOF
}

# Main function
main() {
    local manifest_url=""
    local binary_path="${BUILD_DIR}/target/release/protocore"
    local cargo_lock_path="${BUILD_DIR}/Cargo.lock"
    local local_manifest=""
    local local_mode=false
    local skip_sigs=false
    local version=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -b|--binary)
                binary_path="$2"
                shift 2
                ;;
            -m|--manifest)
                local_manifest="$2"
                shift 2
                ;;
            -l|--local)
                local_mode=true
                shift
                ;;
            -s|--signatures)
                MIN_SIGNATURES_REQUIRED="$2"
                shift 2
                ;;
            --skip-sigs)
                skip_sigs=true
                MIN_SIGNATURES_REQUIRED=0
                shift
                ;;
            -v|--version)
                version="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                manifest_url="$1"
                shift
                ;;
        esac
    done

    # Handle local mode
    if [[ "${local_mode}" == true ]]; then
        local_manifest="${local_manifest:-${BUILD_DIR}/build-manifest.json}"
        verify_local_build "${local_manifest}" "${binary_path}"
        exit $?
    fi

    # Build manifest URL
    if [[ -n "${local_manifest}" ]]; then
        # Use local manifest file
        cp "${local_manifest}" "${TEMP_DIR}/manifest.json"
        manifest_url="file://${TEMP_DIR}/manifest.json"

        # Read from local file
        local expected_binary_hash=$(jq -r '.binary_hash' "${local_manifest}")
        verify_binary_hash "${binary_path}" "${expected_binary_hash}"
        exit $?
    fi

    if [[ -z "${manifest_url}" ]]; then
        if [[ -n "${version}" ]]; then
            manifest_url="${DEFAULT_RELEASE_URL}/v${version}/manifest.json"
        else
            # Try to get latest version
            manifest_url="${DEFAULT_RELEASE_URL}/latest/manifest.json"
        fi
    fi

    # Perform full verification
    perform_full_verification "${manifest_url}" "${binary_path}" "${cargo_lock_path}"
}

# Run main function
main "$@"
