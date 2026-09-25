#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' 0 1 2 3 15

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_passes() {
    description=$1
    shift
    "$@" >"$root/output" 2>&1 || {
        cat "$root/output" >&2
        fail "$description"
    }
}

assert_fails_with() {
    description=$1
    expected=$2
    shift 2
    if "$@" >"$root/output" 2>&1; then
        fail "$description"
    fi
    grep -Fq "$expected" "$root/output" || {
        cat "$root/output" >&2
        fail "$description did not report: $expected"
    }
}

fixture=$root/readelf
mkdir -p "$fixture"
: >"$root/keyhold"

cat >"$root/fake-readelf" <<'EOF'
#!/bin/sh
case "$1" in
    -h) cat "$TEST_READELF_FIXTURE/header" ;;
    -lW) cat "$TEST_READELF_FIXTURE/program" ;;
    -dW) cat "$TEST_READELF_FIXTURE/dynamic" ;;
    --version-info) cat "$TEST_READELF_FIXTURE/version" ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$root/fake-readelf"
export TEST_READELF_FIXTURE="$fixture"
READELF=$root/fake-readelf
export READELF

write_elf_fixture() {
    machine=$1
    interpreter=$2
    needed=$3
    versions=$4
    printf '  Type:                              DYN (Position-Independent Executable file)\n  Machine:                           %s\n' "$machine" >"$fixture/header"
    printf '%s\n' "$interpreter" >"$fixture/program"
    printf '%s\n' "$needed" >"$fixture/dynamic"
    printf '%s\n' "$versions" >"$fixture/version"
}

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.2.5  Name: GLIBC_2.28'
assert_passes 'valid x86_64 GNU ELF was rejected' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"
grep -Fq 'maximum GLIBC requirement: 2.28' "$root/output" || \
    fail 'GNU verification did not report its maximum GLIBC version'

write_elf_fixture 'AArch64' \
    '  INTERP         0x0000000000000238' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.17  Name: GLIBC_2.28'
assert_passes 'valid aarch64 GNU ELF was rejected' \
    ./scripts/verify-release-binary.sh gnu aarch64 "$root/keyhold"

printf '  Type: DYN (Position-Independent Executable file)\n  Machine: AArch64\n' >"$fixture/header"
assert_passes 'valid ELF header with compact spacing was rejected' \
    ./scripts/verify-release-binary.sh gnu aarch64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' '' '' ''
assert_passes 'valid static musl ELF was rejected' \
    ./scripts/verify-release-binary.sh musl x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.29'
assert_fails_with 'new GLIBC symbol was accepted' 'newer than 2.28' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' ''
assert_fails_with 'missing GLIBC metadata was accepted' \
    'no GLIBC symbol versions found' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"

write_elf_fixture 'AArch64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.28'
assert_fails_with 'wrong ELF architecture was accepted' \
    'expected x86_64 ELF' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' '' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.28'
assert_fails_with 'GNU ELF without an interpreter was accepted' \
    'has no PT_INTERP' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' '' ''
assert_fails_with 'dynamic musl ELF was accepted' 'must not contain PT_INTERP' \
    ./scripts/verify-release-binary.sh musl x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' '' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libz.so.1]' ''
assert_fails_with 'musl ELF with NEEDED dependencies was accepted' \
    'must not contain NEEDED dependencies' \
    ./scripts/verify-release-binary.sh musl x86_64 "$root/keyhold"

assets=$root/assets
targets='x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl'

create_assets() {
    rm -rf "$assets"
    mkdir "$assets"
    for target in $targets; do
        archive="keyhold-v9.8.7-$target.tar.gz"
        printf '%s\n' "$target" >"$assets/$archive"
        (cd "$assets" && sha256sum "$archive" >"$archive.sha256")
    done
}

create_assets
assert_passes 'complete release asset set was rejected' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
rm "$assets/keyhold-v9.8.7-x86_64-unknown-linux-gnu.tar.gz"
assert_fails_with 'missing archive was accepted' 'missing or empty release asset' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
: >"$assets/keyhold-v9.8.7-x86_64-unknown-linux-musl.tar.gz"
assert_fails_with 'empty archive was accepted' 'missing or empty release asset' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
printf 'unexpected\n' >"$assets/extra.txt"
assert_fails_with 'unexpected file was accepted' 'unexpected release asset' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
printf 'malformed\n' >"$assets/keyhold-v9.8.7-aarch64-unknown-linux-gnu.tar.gz.sha256"
assert_fails_with 'malformed checksum was accepted' 'checksum verification failed' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
sidecar=$assets/keyhold-v9.8.7-aarch64-unknown-linux-musl.tar.gz.sha256
sed 's/aarch64-unknown-linux-musl/x86_64-unknown-linux-musl/' "$sidecar" >"$sidecar.new"
mv "$sidecar.new" "$sidecar"
assert_fails_with 'checksum for wrong filename was accepted' \
    'checksum verification failed' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
sidecar=$assets/keyhold-v9.8.7-aarch64-unknown-linux-musl.tar.gz.sha256
(cd "$assets" && sha256sum keyhold-v9.8.7-x86_64-unknown-linux-musl.tar.gz >"$sidecar")
assert_fails_with 'sidecar validating another existing archive was accepted' \
    'checksum verification failed' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
printf 'hidden\n' >"$assets/.unexpected"
assert_fails_with 'hidden unexpected file was accepted' 'unexpected release asset' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

create_assets
printf 'changed\n' >>"$assets/keyhold-v9.8.7-x86_64-unknown-linux-gnu.tar.gz"
assert_fails_with 'checksum mismatch was accepted' 'checksum verification failed' \
    ./scripts/verify-release-assets.sh v9.8.7 "$assets"

printf 'Release verification tests passed: 19 cases.\n'
