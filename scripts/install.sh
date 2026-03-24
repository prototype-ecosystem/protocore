#!/usr/bin/env bash
set -euo pipefail

# Proto Core installer — builds from source, installs binary + systemd service
# Usage: ./scripts/install.sh [--no-build] [--user USERNAME] [--data-dir PATH]

PROTOCORE_USER="${PROTOCORE_USER:-protocore}"
PROTOCORE_DATA_DIR="${PROTOCORE_DATA_DIR:-/var/lib/protocore}"
PROTOCORE_CONFIG_DIR="/etc/protocore"
PROTOCORE_LOG_DIR="/var/log/protocore"
PROTOCORE_BIN="/usr/local/bin/protocore"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
NO_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-build)   NO_BUILD=true; shift ;;
        --user)       PROTOCORE_USER="$2"; shift 2 ;;
        --data-dir)   PROTOCORE_DATA_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--no-build] [--user USERNAME] [--data-dir PATH]"
            echo ""
            echo "Options:"
            echo "  --no-build    Skip cargo build, use existing binary"
            echo "  --user NAME   System user to run as (default: protocore)"
            echo "  --data-dir    Data directory (default: /var/lib/protocore)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

info()    { echo -e "\033[32m[+]\033[0m $1"; }
warn()    { echo -e "\033[33m[!]\033[0m $1"; }
error()   { echo -e "\033[31m[x]\033[0m $1"; exit 1; }

# Must be root
[[ $EUID -eq 0 ]] || error "Run as root: sudo $0"

info "Installing Proto Core"

# 1. Build
if [[ "$NO_BUILD" == false ]]; then
    info "Building from source (release mode)..."
    if ! command -v cargo &>/dev/null; then
        error "Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi
    cd "$REPO_DIR"
    cargo build --release --bin protocore
    BUILT_BIN="$REPO_DIR/target/release/protocore"
else
    BUILT_BIN="$REPO_DIR/target/release/protocore"
    [[ -f "$BUILT_BIN" ]] || error "No binary at $BUILT_BIN — build first or remove --no-build"
fi

# 2. Create system user
if ! id "$PROTOCORE_USER" &>/dev/null; then
    info "Creating system user: $PROTOCORE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$PROTOCORE_USER"
fi

# 3. Install binary
info "Installing binary to $PROTOCORE_BIN"
install -m 0755 "$BUILT_BIN" "$PROTOCORE_BIN"

# 4. Create directories
info "Creating directories"
install -d -m 0750 -o "$PROTOCORE_USER" -g "$PROTOCORE_USER" "$PROTOCORE_DATA_DIR"
install -d -m 0750 -o "$PROTOCORE_USER" -g "$PROTOCORE_USER" "$PROTOCORE_LOG_DIR"
install -d -m 0750 -o root -g "$PROTOCORE_USER" "$PROTOCORE_CONFIG_DIR"

# 5. Copy config if not exists
if [[ ! -f "$PROTOCORE_CONFIG_DIR/config.toml" ]]; then
    if [[ -f "$REPO_DIR/testnet/config.toml" ]]; then
        info "Copying default config"
        install -m 0640 -o root -g "$PROTOCORE_USER" "$REPO_DIR/testnet/config.toml" "$PROTOCORE_CONFIG_DIR/config.toml"
        # Update data_dir in config to match install location
        sed -i "s|data_dir = .*|data_dir = \"$PROTOCORE_DATA_DIR\"|" "$PROTOCORE_CONFIG_DIR/config.toml"
    else
        warn "No config found — create $PROTOCORE_CONFIG_DIR/config.toml manually"
    fi
else
    info "Config exists, skipping (use --force-config to overwrite)"
fi

# 6. Install systemd service
info "Installing systemd service"
TMPSERVICE=$(mktemp)
sed \
    -e "s|User=protocore|User=$PROTOCORE_USER|" \
    -e "s|Group=protocore|Group=$PROTOCORE_USER|" \
    -e "s|/var/lib/protocore|$PROTOCORE_DATA_DIR|" \
    "$SCRIPT_DIR/protocore.service" > "$TMPSERVICE"
install -m 0644 "$TMPSERVICE" /etc/systemd/system/protocore.service
rm -f "$TMPSERVICE"

systemctl daemon-reload
systemctl enable protocore

# 7. Print status
info "Installation complete!"
echo ""
echo "  Binary:   $PROTOCORE_BIN"
echo "  Config:   $PROTOCORE_CONFIG_DIR/config.toml"
echo "  Data:     $PROTOCORE_DATA_DIR"
echo "  Logs:     journalctl -u protocore -f"
echo "  Service:  systemctl {start|stop|status} protocore"
echo ""

if [[ ! -f "$PROTOCORE_CONFIG_DIR/validator.key" ]]; then
    warn "No validator key found. To run as validator:"
    echo "  1. Generate key:  protocore keys generate --output $PROTOCORE_CONFIG_DIR/validator.key"
    echo "  2. Set ownership: chown $PROTOCORE_USER:$PROTOCORE_USER $PROTOCORE_CONFIG_DIR/validator.key"
    echo "  3. Start:         systemctl start protocore"
else
    echo "Start with: systemctl start protocore"
fi
