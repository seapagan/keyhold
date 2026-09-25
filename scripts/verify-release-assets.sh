#!/bin/sh
set -eu

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

test "$#" -eq 2 || die 'usage: verify-release-assets.sh <tag> <directory>'

tag=$1
directory=$2
test -d "$directory" || die "artifact directory not found: $directory"

targets='x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl'

for path in "$directory"/.[!.]* "$directory"/..?* "$directory"/*; do
    test -e "$path" || continue
    test -f "$path" || die "unexpected release asset: $path"
    name=${path##*/}
    case "$name" in
        "keyhold-$tag-x86_64-unknown-linux-gnu.tar.gz"|\
        "keyhold-$tag-x86_64-unknown-linux-gnu.tar.gz.sha256"|\
        "keyhold-$tag-x86_64-unknown-linux-musl.tar.gz"|\
        "keyhold-$tag-x86_64-unknown-linux-musl.tar.gz.sha256"|\
        "keyhold-$tag-aarch64-unknown-linux-gnu.tar.gz"|\
        "keyhold-$tag-aarch64-unknown-linux-gnu.tar.gz.sha256"|\
        "keyhold-$tag-aarch64-unknown-linux-musl.tar.gz"|\
        "keyhold-$tag-aarch64-unknown-linux-musl.tar.gz.sha256") ;;
        *) die "unexpected release asset: $name" ;;
    esac
done

for target in $targets; do
    archive="keyhold-$tag-$target.tar.gz"
    sidecar="$archive.sha256"
    test -s "$directory/$archive" && test -s "$directory/$sidecar" || \
        die "missing or empty release asset: $archive or $sidecar"
    awk -v expected="$archive" '
        NR == 1 && NF == 2 && length($1) == 64 &&
            $1 !~ /[^0-9a-fA-F]/ && $2 == expected { valid = 1 }
        END { exit !(NR == 1 && valid) }
    ' "$directory/$sidecar" || \
        die "checksum verification failed: $sidecar"
    (cd "$directory" && sha256sum -c "$sidecar") || \
        die "checksum verification failed: $sidecar"
done

printf 'verified 4 release archives and 4 checksum sidecars\n'
