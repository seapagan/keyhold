#!/bin/sh
set -eu

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os:$arch" in
        Linux:x86_64|Linux:amd64) printf '%s\n' x86_64-unknown-linux-gnu ;;
        Linux:aarch64|Linux:arm64) printf '%s\n' aarch64-unknown-linux-gnu ;;
        *)
            printf 'error: unsupported platform: %s/%s\n' "$os" "$arch" >&2
            return 1
            ;;
    esac
}

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        printf 'error: curl or wget is required\n' >&2
        return 1
    fi
}

main() {
    target=$(detect_target)
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' 0
    trap 'exit 1' 1 2 3 15

    version=${KEYHOLD_VERSION:-}
    if [ -z "$version" ]; then
        download \
            'https://api.github.com/repos/seapagan/keyhold/releases/latest' \
            "$tmp_dir/latest.json"
        version=$(sed -n \
            's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            "$tmp_dir/latest.json" | head -n 1)
        if [ -z "$version" ]; then
            printf 'error: latest release tag was not found\n' >&2
            return 1
        fi
    fi

    install_dir=${KEYHOLD_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}
    asset="keyhold-${version}-${target}.tar.gz"
    download \
        "https://github.com/seapagan/keyhold/releases/download/${version}/${asset}" \
        "$tmp_dir/$asset"
    tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
    if [ ! -f "$tmp_dir/keyhold" ]; then
        printf 'error: release archive is missing keyhold\n' >&2
        return 1
    fi

    mkdir -p "$install_dir"
    install -m 755 "$tmp_dir/keyhold" "$install_dir/keyhold"
    printf 'Installed keyhold %s to %s.\n' "$version" "$install_dir"

    case ":${PATH:-}:" in
        *":$install_dir:"*) ;;
        *)
            printf 'warning: %s is not on PATH; add it to PATH to use keyhold.\n' \
                "$install_dir" >&2
            ;;
    esac
}

main "$@"
