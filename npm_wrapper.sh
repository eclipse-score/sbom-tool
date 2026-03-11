#!/usr/bin/env bash
# Wrapper to use system-installed npm/cdxgen.
# Resolves npm and cdxgen from PATH, with optional NVM support via $NVM_DIR.

# Load NVM if available (honours NVM_DIR env var set by the caller; no
# hard-coded version or home directory).
if [[ -n "${NVM_DIR:-}" && -s "${NVM_DIR}/nvm.sh" ]]; then
    # shellcheck source=/dev/null
    source "${NVM_DIR}/nvm.sh" --no-use
    # Use whatever version is currently active/default in NVM.
    nvm use --silent 2>/dev/null || true
fi

# Fail clearly if npm is not on PATH.
if ! command -v npm &>/dev/null; then
    echo "npm_wrapper.sh: 'npm' not found in PATH. Install Node.js (e.g. via nvm) and ensure it is on PATH." >&2
    exit 1
fi

# If called with "exec -- @cyclonedx/cdxgen", resolve and run cdxgen directly.
if [[ "$1" == "exec" && "$2" == "--" && "$3" == "@cyclonedx/cdxgen" ]]; then
    shift 3
    if ! command -v cdxgen &>/dev/null; then
        echo "npm_wrapper.sh: 'cdxgen' not found in PATH. Install it with: npm install -g @cyclonedx/cdxgen" >&2
        exit 1
    fi
    exec cdxgen "$@"
else
    exec npm "$@"
fi
