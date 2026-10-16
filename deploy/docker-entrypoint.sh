#!/bin/sh
set -e

# Fix data directory permissions when running as root.
# Docker named volumes / host bind-mounts may be owned by root,
# preventing the non-root sub2api user from writing files.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/data
    # Use || true to avoid failure on read-only mounted files (e.g. config.yaml:ro)
    chown -R sub2api:sub2api /app/data 2>/dev/null || true
    # Re-invoke this script as sub2api so the flag-detection below
    # also runs under the correct user.
    exec su-exec sub2api "$0" "$@"
fi

# Compatibility: if the first arg looks like a flag (e.g. --help),
# prepend the default binary so it behaves the same as the old
# ENTRYPOINT ["/app/sub2api"] style.
if [ "${1#-}" != "$1" ]; then
    set -- /app/sub2api "$@"
fi

# ZCode's web updater replaces the executable in place. Keep that executable
# in the existing data volume so container recreation preserves web upgrades.
# Explicitly opt in; ordinary images and custom commands retain their behavior.
if [ "${SUB2API_UPDATE_CHANNEL:-}" = "zcode" ] && [ "${1:-}" = "/app/sub2api" ]; then
    binary_dir=/app/data/zcode-bin
    binary_path="$binary_dir/sub2api"
    mkdir -p "$binary_dir"
    if [ ! -e "$binary_path" ]; then
        /app/sub2api -version | grep -q 'build_type: zcode' || {
            echo "ZCode persistent updates require a compatible image" >&2
            exit 1
        }
        cp /app/sub2api "$binary_path.tmp"
        chmod 755 "$binary_path.tmp"
        mv "$binary_path.tmp" "$binary_path"
    fi
    "$binary_path" -version | grep -q 'build_type: zcode' || {
        echo "Persisted executable is not a compatible ZCode build" >&2
        exit 1
    }
    shift
    set -- "$binary_path" "$@"
fi

exec "$@"
