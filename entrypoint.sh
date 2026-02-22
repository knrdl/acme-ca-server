#!/bin/sh
# entrypoint.sh for https://github.com/knrdl/acme-ca-server/
set -euo pipefail

# if command starts with "uvicorn", create environment variables from 
#   files with uppercase names from /run/secrets/*
if [ -d /run/secrets ]; then
    for __FILE in /run/secrets/*; do
        [ -f "$__FILE" ] || continue
        __FILENAME=$(basename "$__FILE")
        [ "$__FILENAME" = "_" ] && continue
        echo "$__FILENAME" | grep -q '^[A-Z0-9_]\+$' || continue
        [ -r "$__FILE" ] || { echo "Warning: Cannot read secret file: '$__FILE'. Consider setting secret 'mode:400' and 'uid:$(id -u)'" >&2; continue; }
        [ -s "$__FILE" ] && export "${__FILENAME}"="$(head -n 1 "$__FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    done
fi

# if PGPASSFILE is provided, check it's ownership.
# On Windows Docker Desktop, ownership and permissions can not be set correctly and asyncpg fails with 
#   UserWarning: password file PosixPath('...') has group or world access; ...
# The indicator is: we can read this file, but we (non-root user) are not owner. 
#   Also /sys/devices/platform/MSFT*:* or /sys/devices/platform/HYPER_V*:* exists
# In this case,  file contents need to be copied to file with correct permissions
if [ -n "${PGPASSFILE:-}" ] && [ -f "$PGPASSFILE" ] && [ -r "$PGPASSFILE" ] && [ -s "$PGPASSFILE" ] && [ ! -O "$PGPASSFILE" ]; then
    if [ -e /sys/devices/platform/MSFT*:* ] || [ -e /sys/devices/platform/HYPER_V*:* ]; then
        __OLD_PGPASSFILE="${PGPASSFILE}"
        PGPASSFILE="/dev/shm/$(id -u -n)/.pgpassfile"
        export PGPASSFILE
        mkdir -p  "$(dirname "$PGPASSFILE")"
        chmod 700 "$(dirname "$PGPASSFILE")"
        cp -f "$__OLD_PGPASSFILE" "$PGPASSFILE"
        chmod 400 "$PGPASSFILE"
        echo "WARNING: permission fix applied to PGPASSFILE: '$__OLD_PGPASSFILE' was copied to '${PGPASSFILE}' and \$PGPASSFILE was changed respectively"
    fi
fi


exec "$@"