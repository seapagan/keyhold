#!/bin/sh
set -eu

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

test "$#" -eq 3 || die 'usage: verify-release-binary.sh <gnu|musl> <x86_64|aarch64> <binary>'

libc=$1
arch=$2
binary=$3
readelf=${READELF:-readelf}

test -f "$binary" || die "binary not found: $binary"

header=$($readelf -h "$binary") || die 'readelf could not inspect the ELF header'
printf '%s\n' "$header" | grep -Eq 'Type:[[:space:]]+(EXEC|DYN)' || \
    die 'binary is not an executable ELF'

case "$arch" in
    x86_64) machine='Advanced Micro Devices X86-64' ;;
    aarch64) machine='AArch64' ;;
    *) die "unsupported architecture: $arch" ;;
esac
printf '%s\n' "$header" | grep -Eq "Machine:[[:space:]]+$machine" || \
    die "expected $arch ELF"

program=$($readelf -lW "$binary") || die 'readelf could not inspect program headers'
dynamic=$($readelf -dW "$binary") || die 'readelf could not inspect dynamic dependencies'

case "$libc" in
    gnu)
        printf '%s\n' "$program" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' || \
            die 'GNU ELF has no PT_INTERP program header'
        printf '%s\n' "$dynamic" | grep -Eq '\(NEEDED\)' || \
            die 'GNU ELF has no dynamic NEEDED dependencies'
        version_info=$($readelf --version-info -W "$binary") || \
            die 'readelf could not inspect GLIBC symbol versions'
        versions=$(printf '%s\n' "$version_info" | \
            grep -Eo 'GLIBC_[0-9]+\.[0-9]+' | sort -u || :)
        test -n "$versions" || die 'no GLIBC symbol versions found'
        max_major=0
        max_minor=0
        for version in $versions; do
            numbers=${version#GLIBC_}
            major=${numbers%%.*}
            minor=${numbers#*.}
            if test "$major" -gt "$max_major" || {
                test "$major" -eq "$max_major" && test "$minor" -gt "$max_minor"
            }; then
                max_major=$major
                max_minor=$minor
            fi
        done
        printf 'maximum GLIBC requirement: %s.%s\n' "$max_major" "$max_minor"
        if test "$max_major" -gt 2 || {
            test "$max_major" -eq 2 && test "$max_minor" -gt 28
        }; then
            die "GLIBC requirement $max_major.$max_minor is newer than 2.28"
        fi
        ;;
    musl)
        if printf '%s\n' "$program" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
            die 'static musl ELF must not contain PT_INTERP'
        fi
        if printf '%s\n' "$dynamic" | grep -Eq '\(NEEDED\)'; then
            die 'static musl ELF must not contain NEEDED dependencies'
        fi
        printf 'static musl ELF verified\n'
        ;;
    *) die "unsupported libc family: $libc" ;;
esac
