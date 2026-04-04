#!/bin/bash
set -e

TOKEN_DIR="/var/lib/softhsmv3/tokens"
SOFTHSM_CONF="/etc/softhsmv3.conf"
TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-TestToken}"
TOKEN_PIN="${SOFTHSM_TOKEN_PIN:-1234}"
TOKEN_SO_PIN="${SOFTHSM_TOKEN_SO_PIN:-12345678}"
APP_UID=10001

export SOFTHSM2_CONF="${SOFTHSM_CONF}"
export LD_LIBRARY_PATH=/opt/openssl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

mkdir -p "${TOKEN_DIR}"

# Determine the correct CLI tool name (softhsmv3 may ship as softhsm2-util or softhsm3-util)
if command -v softhsm3-util &>/dev/null; then
    SOFTHSM_UTIL=softhsm3-util
elif command -v softhsm2-util &>/dev/null; then
    SOFTHSM_UTIL=softhsm2-util
else
    echo "ERROR: No softhsm utility found in PATH." >&2
    exit 1
fi

echo "[softhsm] Using utility: ${SOFTHSM_UTIL}"

# Fix volume ownership (may be root-owned from a previous build)
chown -R "${APP_UID}:0" "${TOKEN_DIR}" 2>/dev/null || true

# Check if the token is already initialized and valid
TOKEN_VALID=false
if [ -n "$(ls -A ${TOKEN_DIR} 2>/dev/null)" ]; then
    if "${SOFTHSM_UTIL}" --show-slots 2>/dev/null | grep -q "Label:.*${TOKEN_LABEL}"; then
        TOKEN_VALID=true
        echo "[softhsm] Token '${TOKEN_LABEL}' found and valid."
    else
        echo "[softhsm] Token directory has stale/invalid data — cleaning up."
        rm -rf "${TOKEN_DIR:?}"/* 2>/dev/null || true
    fi
fi

if [ "$TOKEN_VALID" = false ]; then
    echo "[softhsm] Initializing token '${TOKEN_LABEL}'..."
    "${SOFTHSM_UTIL}" \
        --init-token \
        --free \
        --label  "${TOKEN_LABEL}" \
        --pin    "${TOKEN_PIN}" \
        --so-pin "${TOKEN_SO_PIN}"
    # Ensure new token files are owned by the app user
    chown -R "${APP_UID}:0" "${TOKEN_DIR}" 2>/dev/null || true
    echo "[softhsm] Token '${TOKEN_LABEL}' initialized."
fi

"${SOFTHSM_UTIL}" --show-slots 2>/dev/null || true
echo "[softhsm] PKCS#11 library: $(ls /usr/local/lib/softhsm/libsofthsm*.so 2>/dev/null | head -1)"

# Drop to non-root app user and hand off to EJBCA
exec gosu "${APP_UID}" /opt/keyfactor/bin/start.sh "$@"
