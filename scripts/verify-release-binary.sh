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
            grep -Eo 'GLIBC_[0-9]+(\.[0-9]+)+' | sort -Vu || :)
        test -n "$versions" || die 'no GLIBC symbol versions found'
        max_version=$(printf '%s\n' "$versions" | sed 's/^GLIBC_//' | sort -V | tail -n 1)
        printf 'maximum GLIBC requirement: %s\n' "$max_version"
        newest=$(printf '%s\n' "$max_version" '2.28' | sort -V | tail -n 1)
        if test "$newest" != '2.28'; then
            die "GLIBC requirement $max_version is newer than 2.28"
        fi
        ;;
    musl)
        if printf '%s\n' "$program" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
            die 'static musl ELF must not contain PT_INTERP'
        fi
        if printf '%s\n' "$dynamic" | grep -Eq '\(NEEDED\)'; then
            die 'static musl ELF must not contain NEEDED dependencies'
        fi
        notes=$($readelf -nW "$binary") || die 'readelf could not inspect ELF notes'
        if printf '%s\n' "$notes" | grep -Fq 'NT_GNU_ABI_TAG'; then
            die 'static ELF carries a GNU/glibc ABI note, not musl'
        fi
        symbols=$($readelf -sW "$binary") || die 'readelf could not inspect ELF symbols'
        printf '%s\n' "$symbols" | grep -Eq '[[:space:]]__init_libc$' || \
            die 'static ELF does not contain the musl __init_libc symbol'
        printf 'static musl ELF verified: no PT_INTERP, no NEEDED entries, musl __init_libc present\n'
        ;;
    *) die "unsupported libc family: $libc" ;;
esac
