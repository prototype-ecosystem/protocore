#!/bin/bash
# scripts/sign-release.sh
# Release signing script for Proto Core core team members
# Supports hardware keys (YubiKey, Ledger) and GPG signing

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
TARGET_BINARY="${BUILD_DIR}/target/release/protocore"
MANIFEST_FILE="${BUILD_DIR}/build-manifest.json"
SIGNATURES_DIR="${BUILD_DIR}/signatures"

# Signing methods
SIGN_METHOD=${SIGN_METHOD:-"gpg"}  # gpg, pkcs11, ledger

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

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if binary exists
    if [[ ! -f "${TARGET_BINARY}" ]]; then
        log_error "Binary not found at ${TARGET_BINARY}"
        log_error "Please run reproducible-build.sh first."
        exit 1
    fi

    # Check if manifest exists
    if [[ ! -f "${MANIFEST_FILE}" ]]; then
        log_error "Build manifest not found at ${MANIFEST_FILE}"
        log_error "Please run reproducible-build.sh first."
        exit 1
    fi

    # Create signatures directory
    mkdir -p "${SIGNATURES_DIR}"

    log_success "Prerequisites check passed."
}

# Function to get signer identity
get_signer_identity() {
    local identity=""

    case "${SIGN_METHOD}" in
        gpg)
            # Get GPG key ID
            identity=$(gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep -E "^sec" | head -1 | awk '{print $2}' | cut -d'/' -f2)
            if [[ -z "${identity}" ]]; then
                log_error "No GPG secret key found."
                exit 1
            fi
            ;;
        pkcs11|yubikey)
            # Get certificate subject from PKCS#11 token
            if command -v pkcs11-tool &> /dev/null; then
                identity=$(pkcs11-tool --list-objects --type cert 2>/dev/null | grep "label:" | head -1 | cut -d':' -f2 | xargs)
            fi
            if [[ -z "${identity}" ]]; then
                identity="PKCS11_SIGNER"
            fi
            ;;
        ledger)
            identity="LEDGER_HARDWARE_WALLET"
            ;;
        *)
            log_error "Unknown signing method: ${SIGN_METHOD}"
            exit 1
            ;;
    esac

    echo "${identity}"
}

# Function to create signing message
create_signing_message() {
    local version="$1"
    local binary_hash="$2"
    local manifest_hash="$3"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Create canonical signing message
    cat << EOF
PROTOCORE_RELEASE_SIGNATURE
===========================
Version: ${version}
Binary Hash (SHA-256): ${binary_hash}
Manifest Hash (SHA-256): ${manifest_hash}
Timestamp: ${timestamp}
===========================
EOF
}

# Function to sign with GPG
sign_with_gpg() {
    local message_file="$1"
    local signature_file="$2"
    local key_id="$3"

    log_info "Signing with GPG key: ${key_id}"

    gpg --armor \
        --local-user "${key_id}" \
        --output "${signature_file}" \
        --detach-sign "${message_file}"

    log_success "GPG signature created: ${signature_file}"
}

# Function to sign with PKCS#11 (hardware key)
sign_with_pkcs11() {
    local message_file="$1"
    local signature_file="$2"

    log_info "Signing with PKCS#11 hardware token..."
    log_warn "Please insert your hardware key and enter PIN when prompted."

    if ! command -v pkcs11-tool &> /dev/null; then
        log_error "pkcs11-tool not found. Install OpenSC package."
        exit 1
    fi

    # Sign using PKCS#11 token
    pkcs11-tool --sign \
        --mechanism SHA256-RSA-PKCS \
        --input-file "${message_file}" \
        --output-file "${signature_file}" \
        --signature-format openssl

    log_success "PKCS#11 signature created: ${signature_file}"
}

# Function to sign with Ledger hardware wallet
sign_with_ledger() {
    local message_file="$1"
    local signature_file="$2"

    log_info "Signing with Ledger hardware wallet..."
    log_warn "Please connect your Ledger device and approve the signature."

    # Create message hash for Ledger signing
    local message_hash=$(compute_sha256 "${message_file}")

    echo ""
    echo "=============================================="
    echo "  LEDGER SIGNING INSTRUCTIONS"
    echo "=============================================="
    echo ""
    echo "1. Connect your Ledger device"
    echo "2. Open the Ethereum or appropriate signing app"
    echo "3. Navigate to 'Sign Message'"
    echo "4. Sign the following hash:"
    echo ""
    echo "   ${message_hash}"
    echo ""
    echo "5. Enter your signature below (hex format):"
    echo ""

    read -p "Signature: " ledger_sig

    # Validate signature format (basic hex check)
    if [[ ! "${ledger_sig}" =~ ^[0-9a-fA-F]+$ ]]; then
        log_error "Invalid signature format. Expected hex string."
        exit 1
    fi

    # Store the signature
    echo "${ledger_sig}" > "${signature_file}"

    log_success "Ledger signature recorded: ${signature_file}"
}

# Function to perform manual signing (fallback)
sign_manual() {
    local message_file="$1"
    local signature_file="$2"
    local signer_name="$3"

    echo ""
    echo "=============================================="
    echo "  MANUAL SIGNING INSTRUCTIONS"
    echo "=============================================="
    echo ""
    echo "Sign the following message with your hardware key:"
    echo ""
    echo "---BEGIN MESSAGE---"
    cat "${message_file}"
    echo "---END MESSAGE---"
    echo ""
    echo "Message file location: ${message_file}"
    echo ""
    echo "Options:"
    echo "  1. Use your hardware security key's signing tool"
    echo "  2. Use an air-gapped signing machine"
    echo "  3. Use a mobile hardware wallet app"
    echo ""
    echo "After signing, either:"
    echo "  a) Paste the signature below"
    echo "  b) Save signature to: ${signature_file}"
    echo ""

    read -p "Enter signature (or press Enter if saved to file): " manual_sig

    if [[ -n "${manual_sig}" ]]; then
        echo "${manual_sig}" > "${signature_file}"
        log_success "Signature saved to: ${signature_file}"
    elif [[ -f "${signature_file}" ]]; then
        log_success "Signature file found: ${signature_file}"
    else
        log_error "No signature provided."
        exit 1
    fi
}

# Function to create signature bundle
create_signature_bundle() {
    local version="$1"
    local signer_id="$2"
    local signature_file="$3"
    local message_file="$4"

    local bundle_file="${SIGNATURES_DIR}/${version}-${signer_id}-signature.json"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local signature_content=$(cat "${signature_file}" | tr -d '\n')
    local message_hash=$(compute_sha256 "${message_file}")

    cat > "${bundle_file}" << EOF
{
    "version": "${version}",
    "signer_id": "${signer_id}",
    "sign_method": "${SIGN_METHOD}",
    "timestamp": "${timestamp}",
    "message_hash": "${message_hash}",
    "signature": "${signature_content}",
    "signature_file": "$(basename "${signature_file}")"
}
EOF

    log_success "Signature bundle created: ${bundle_file}"
    echo "${bundle_file}"
}

# Function to verify own signature
verify_signature() {
    local message_file="$1"
    local signature_file="$2"

    log_info "Verifying signature..."

    case "${SIGN_METHOD}" in
        gpg)
            if gpg --verify "${signature_file}" "${message_file}" 2>/dev/null; then
                log_success "GPG signature verified successfully."
                return 0
            else
                log_error "GPG signature verification failed."
                return 1
            fi
            ;;
        pkcs11|yubikey)
            log_info "PKCS#11 signature verification requires the public key."
            log_warn "Please verify manually with your organization's verification tool."
            return 0
            ;;
        ledger)
            log_info "Ledger signature verification requires the public key."
            log_warn "Please verify manually with your organization's verification tool."
            return 0
            ;;
        *)
            log_warn "Manual verification required for signature method: ${SIGN_METHOD}"
            return 0
            ;;
    esac
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] VERSION

Sign a Proto Core release binary for multi-signature verification.

Arguments:
    VERSION     Version string of the release to sign (required)

Options:
    -h, --help          Show this help message
    -m, --method TYPE   Signing method: gpg, pkcs11, yubikey, ledger, manual
                        (default: gpg, or SIGN_METHOD env var)
    -k, --key KEY_ID    Specify GPG key ID to use
    -o, --output DIR    Output directory for signatures
    --verify-only       Only verify existing signature

Environment Variables:
    SIGN_METHOD         Default signing method
    GPG_KEY_ID          GPG key ID to use for signing

Examples:
    $(basename "$0") 1.0.0                    # Sign with default GPG key
    $(basename "$0") -m yubikey 1.0.0         # Sign with YubiKey
    $(basename "$0") -m ledger 1.0.0          # Sign with Ledger
    $(basename "$0") -m manual 1.0.0          # Manual signing instructions

Supported Hardware Keys:
    - YubiKey (via PKCS#11)
    - Ledger Nano S/X
    - Trezor (manual mode)
    - Any PKCS#11 compatible token

EOF
}

# Function to display summary
display_summary() {
    local version="$1"
    local binary_hash="$2"
    local signature_file="$3"
    local bundle_file="$4"

    echo ""
    echo "=============================================="
    echo "       Release Signing Complete"
    echo "=============================================="
    echo ""
    echo "Version:        ${version}"
    echo "Binary Hash:    ${binary_hash}"
    echo "Sign Method:    ${SIGN_METHOD}"
    echo ""
    echo "Files Created:"
    echo "  - Signature: ${signature_file}"
    echo "  - Bundle:    ${bundle_file}"
    echo ""
    echo "Next Steps:"
    echo "  1. Submit your signature bundle to the release coordinator"
    echo "  2. The coordinator will collect signatures from all core team members"
    echo "  3. Once threshold is met, the release will be published"
    echo ""
    echo "=============================================="
}

# Main function
main() {
    local version=""
    local key_id=""
    local verify_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -m|--method)
                SIGN_METHOD="$2"
                shift 2
                ;;
            -k|--key)
                key_id="$2"
                shift 2
                ;;
            -o|--output)
                SIGNATURES_DIR="$2"
                shift 2
                ;;
            --verify-only)
                verify_only=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                version="$1"
                shift
                ;;
        esac
    done

    # Validate version argument
    if [[ -z "${version}" ]]; then
        log_error "Version argument is required."
        show_usage
        exit 1
    fi

    echo ""
    log_info "=========================================="
    log_info "  Proto Core Release Signing"
    log_info "  Version: ${version}"
    log_info "=========================================="
    echo ""

    cd "${BUILD_DIR}"

    check_prerequisites

    # Compute binary hash
    local binary_hash=$(compute_sha256 "${TARGET_BINARY}")
    local manifest_hash=$(compute_sha256 "${MANIFEST_FILE}")

    log_info "Binary SHA-256: ${binary_hash}"
    log_info "Manifest SHA-256: ${manifest_hash}"

    # Get signer identity
    local signer_id
    if [[ -n "${key_id}" ]]; then
        signer_id="${key_id}"
    else
        signer_id=$(get_signer_identity)
    fi
    log_info "Signer ID: ${signer_id}"

    # Create signing message
    local message_file="${SIGNATURES_DIR}/${version}-message.txt"
    create_signing_message "${version}" "${binary_hash}" "${manifest_hash}" > "${message_file}"

    # Create signature file path
    local safe_signer_id=$(echo "${signer_id}" | tr -c '[:alnum:]' '_')
    local signature_file="${SIGNATURES_DIR}/${version}-${safe_signer_id}.sig"

    if [[ "${verify_only}" == true ]]; then
        if [[ -f "${signature_file}" ]]; then
            verify_signature "${message_file}" "${signature_file}"
        else
            log_error "Signature file not found: ${signature_file}"
            exit 1
        fi
        exit 0
    fi

    # Perform signing based on method
    case "${SIGN_METHOD}" in
        gpg)
            sign_with_gpg "${message_file}" "${signature_file}" "${signer_id}"
            ;;
        pkcs11|yubikey)
            sign_with_pkcs11 "${message_file}" "${signature_file}"
            ;;
        ledger)
            sign_with_ledger "${message_file}" "${signature_file}"
            ;;
        manual)
            sign_manual "${message_file}" "${signature_file}" "${signer_id}"
            ;;
        *)
            log_error "Unknown signing method: ${SIGN_METHOD}"
            exit 1
            ;;
    esac

    # Verify the signature
    verify_signature "${message_file}" "${signature_file}"

    # Create signature bundle
    local bundle_file=$(create_signature_bundle "${version}" "${safe_signer_id}" "${signature_file}" "${message_file}")

    display_summary "${version}" "${binary_hash}" "${signature_file}" "${bundle_file}"

    log_success "Release signing complete!"
}

# Run main function
main "$@"
