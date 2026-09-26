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
    -nW) cat "$TEST_READELF_FIXTURE/notes" ;;
    -sW) cat "$TEST_READELF_FIXTURE/symbols" ;;
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
    : >"$fixture/notes"
    : >"$fixture/symbols"
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

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.2.5'
assert_passes 'three-component GLIBC version was rejected' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"
grep -Fq 'maximum GLIBC requirement: 2.2.5' "$root/output" || \
    fail 'GNU verification truncated a three-component GLIBC version'

printf '  Type: DYN (Position-Independent Executable file)\n  Machine: AArch64\n' >"$fixture/header"
assert_passes 'valid ELF header with compact spacing was rejected' \
    ./scripts/verify-release-binary.sh gnu aarch64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' '' '' ''
printf '  6714: 0000000000342ca4   413 FUNC    LOCAL  DEFAULT    9 __init_libc\n' \
    >"$fixture/symbols"
assert_passes 'valid static musl ELF was rejected' \
    ./scripts/verify-release-binary.sh musl x86_64 "$root/keyhold"
grep -Fq 'static musl ELF verified: no PT_INTERP, no NEEDED entries, musl __init_libc present' \
    "$root/output" || fail 'musl verification did not report all established properties'

write_elf_fixture 'Advanced Micro Devices X86-64' '' '' ''
printf '  GNU                  0x00000010 NT_GNU_ABI_TAG (ABI version tag)\n' \
    >"$fixture/notes"
printf '  1933: 00000000004041c0   679 FUNC GLOBAL HIDDEN 5 __libc_start_main\n' \
    >"$fixture/symbols"
assert_fails_with 'static glibc ELF was accepted as musl' \
    'static ELF carries a GNU/glibc ABI note, not musl' \
    ./scripts/verify-release-binary.sh musl x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.29'
assert_fails_with 'new GLIBC symbol was accepted' 'newer than 2.28' \
    ./scripts/verify-release-binary.sh gnu x86_64 "$root/keyhold"

write_elf_fixture 'Advanced Micro Devices X86-64' \
    '  INTERP         0x0000000000000350' \
    ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' \
    'Name: GLIBC_2.28.1'
assert_fails_with 'three-component GLIBC version above the ceiling was accepted' \
    'GLIBC requirement 2.28.1 is newer than 2.28' \
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
    '  INTERP         0x0000000000000350' '' \
    'Name: GLIBC_2.28'
assert_fails_with 'GNU ELF without NEEDED dependencies was accepted' \
    'has no dynamic NEEDED dependencies' \
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

printf 'Release verification tests passed: 14 cases.\n'
