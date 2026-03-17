#!/usr/bin/env bash
#
# Launcher script for claude-compound-bash.
# Downloads a pre-built binary on first use, then execs it.
#
set -euo pipefail

VERSION="0.9.4"
REPO="gwatts/claude-compound-bash"
BINARY_NAME="claude-compound-bash"

# Determine install directory. Prefer CLAUDE_PLUGIN_ROOT if set (plugin mode),
# otherwise fall back to the directory containing this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -n "${CLAUDE_PLUGIN_ROOT:-}" ]]; then
    BIN_DIR="${CLAUDE_PLUGIN_ROOT}/bin"
else
    BIN_DIR="${SCRIPT_DIR}/../bin"
fi

# On Windows (Git Bash/MSYS2), the Go binary has a .exe extension.
EXE_SUFFIX=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) EXE_SUFFIX=".exe" ;;
esac

BINARY="${BIN_DIR}/${BINARY_NAME}${EXE_SUFFIX}"
VERSION_FILE="${BIN_DIR}/.version"

# Map uname output to Go-style OS/arch names.
detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)
            echo "Unsupported OS: ${os}" >&2
            return 1
            ;;
    esac

    case "${arch}" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            echo "Unsupported architecture: ${arch}" >&2
            return 1
            ;;
    esac

    echo "${os}_${arch}"
}

# Download the binary for the current platform and version.
download_binary() {
    local platform="$1"
    local archive_name="${BINARY_NAME}_${platform}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/v${VERSION}/${archive_name}"
    local tmp_dir

    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ccb.XXXXXX")"

    # cleanup_tmp removes the temp directory, with a safety check.
    cleanup_tmp() {
        if [[ -n "${tmp_dir}" && -d "${tmp_dir}" && "${tmp_dir}" == */ccb.* ]]; then
            rm -r "${tmp_dir}"
        fi
    }

    echo "Downloading ${BINARY_NAME} v${VERSION} for ${platform}..." >&2

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL -o "${tmp_dir}/${archive_name}" "${url}"; then
            echo "Download failed: ${url}" >&2
            cleanup_tmp
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q -O "${tmp_dir}/${archive_name}" "${url}"; then
            echo "Download failed: ${url}" >&2
            cleanup_tmp
            return 1
        fi
    else
        echo "Neither curl nor wget found" >&2
        cleanup_tmp
        return 1
    fi

    mkdir -p "${BIN_DIR}"
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"

    # goreleaser places the binary at the archive root.
    if [[ -f "${tmp_dir}/${BINARY_NAME}${EXE_SUFFIX}" ]]; then
        mv "${tmp_dir}/${BINARY_NAME}${EXE_SUFFIX}" "${BINARY}"
    elif [[ -f "${tmp_dir}/${BINARY_NAME}" ]]; then
        mv "${tmp_dir}/${BINARY_NAME}" "${BINARY}"
    else
        echo "Binary not found in archive" >&2
        cleanup_tmp
        return 1
    fi

    chmod +x "${BINARY}"
    echo "${VERSION}" > "${VERSION_FILE}"
    cleanup_tmp
}

# Ensure the correct version of the binary is available.
ensure_binary() {
    if [[ -x "${BINARY}" && -f "${VERSION_FILE}" ]]; then
        local installed_version
        installed_version="$(cat "${VERSION_FILE}")"
        if [[ "${installed_version}" == "${VERSION}" ]]; then
            return 0
        fi
        echo "Upgrading ${BINARY_NAME} from v${installed_version} to v${VERSION}..." >&2
    fi

    local platform
    platform="$(detect_platform)" || return 1
    download_binary "${platform}" || return 1
}

# --install flag: download binary and exit (for pre-caching).
if [[ "${1:-}" == "--install" ]]; then
    ensure_binary
    echo "${BINARY_NAME} v${VERSION} installed at ${BINARY}" >&2
    exit 0
fi

# Normal operation: ensure binary exists, then exec it.
if ! ensure_binary 2>&1 | head -5 >&2; then
    # Download failed — try the binary on PATH (supports go install users).
    if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
        exec "${BINARY_NAME}" "$@"
    fi
    # No binary available at all — exit silently so Claude Code falls through
    # to its normal approval prompt.
    exit 0
fi

exec "${BINARY}" "$@"
