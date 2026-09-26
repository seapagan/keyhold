#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' 0 1 2 3 15

real_bin=$root/real-bin
test_bin=$root/bin
wget_bin=$root/wget-bin
no_download_bin=$root/no-download-bin
no_sha_bin=$root/no-sha-bin
release_dir=$root/release
mkdir -p "$real_bin" "$test_bin" "$wget_bin" "$no_download_bin" \
    "$no_sha_bin" "$release_dir" "$root/archive" "$root/empty" \
    "$root/installer-tmp"

for command in awk cat chmod cp find grep gzip head mkdir rm sed wc; do
    path=$(command -v "$command")
    ln -s "$path" "$real_bin/$command"
done
for directory in "$test_bin" "$wget_bin" "$no_download_bin" "$no_sha_bin"; do
    for path in "$real_bin"/*; do
        ln -s "$path" "$directory/${path##*/}"
    done
done

REAL_INSTALL=$(command -v install)
REAL_MV=$(command -v mv)
REAL_SHA256SUM=$(command -v sha256sum)
REAL_TAR=$(command -v tar)
export REAL_INSTALL REAL_MV REAL_SHA256SUM REAL_TAR

cat >"$test_bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "$TEST_OS" ;;
    -m) printf '%s\n' "$TEST_ARCH" ;;
    *) exit 2 ;;
esac
EOF

cat >"$test_bin/getconf" <<'EOF'
#!/bin/sh
case "$TEST_GETCONF_KIND" in
    glibc) printf 'glibc %s\n' "$TEST_GLIBC_VERSION" ;;
    malformed) printf 'glibc unknown\n' ;;
    unavailable) exit 1 ;;
esac
EOF

cat >"$test_bin/ldd" <<'EOF'
#!/bin/sh
case "$TEST_LDD_KIND" in
    glibc) printf 'ldd (GNU libc) %s\n' "$TEST_GLIBC_VERSION" ;;
    musl) printf 'musl libc (%s)\n' "$TEST_ARCH" >&2 ;;
    malformed) printf 'ldd mystery libc\n' ;;
    unavailable) exit 1 ;;
esac
EOF

cat >"$test_bin/mktemp" <<'EOF'
#!/bin/sh
case "$1" in
    -d)
        count=$(cat "$TEST_MKTEMP_COUNTER")
        count=$((count + 1))
        printf '%s\n' "$count" >"$TEST_MKTEMP_COUNTER"
        directory="$TEST_TMP_PARENT/run-$count"
        mkdir "$directory"
        printf '%s\n' "$directory" >"$TEST_MKTEMP_LAST"
        printf '%s\n' "$directory"
        ;;
    *)
        test "$TEST_STAGE_FAIL" != 1 || exit 1
        count=$(cat "$TEST_STAGE_COUNTER")
        count=$((count + 1))
        printf '%s\n' "$count" >"$TEST_STAGE_COUNTER"
        path=${1%XXXXXX}$count
        : >"$path"
        printf '%s\n' "$path" >"$TEST_STAGE_LAST"
        printf '%s\n' "$path"
        ;;
esac
EOF

cat >"$test_bin/curl" <<'EOF'
#!/bin/sh
url=
destination=
while test "$#" -gt 0; do
    case "$1" in
        -o) destination=$2; shift 2 ;;
        -w) shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >>"$TEST_DOWNLOAD_LOG"
printf 'curl\n' >>"$TEST_DOWNLOADER_LOG"
case "$url" in
    */releases/latest) printf '%s\n' "$TEST_LATEST_URL" ;;
    */releases/download/*)
        name=${url##*/}
        cp "$TEST_RELEASE_DIR/$name" "$destination"
        ;;
    *) exit 1 ;;
esac
EOF

cat >"$test_bin/wget" <<'EOF'
#!/bin/sh
url=
destination=
while test "$#" -gt 0; do
    case "$1" in
        -qO) destination=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >>"$TEST_DOWNLOAD_LOG"
printf 'wget\n' >>"$TEST_DOWNLOADER_LOG"
case "$url" in
    */releases/latest) printf '  Location: %s\n' "$TEST_LATEST_URL" >&2 ;;
    */releases/download/*)
        name=${url##*/}
        cp "$TEST_RELEASE_DIR/$name" "$destination"
        ;;
    *) exit 1 ;;
esac
EOF

cat >"$test_bin/sha256sum" <<'EOF'
#!/bin/sh
printf 'sha256sum\n' >>"$TEST_EVENT_LOG"
exec "$REAL_SHA256SUM" "$@"
EOF

cat >"$test_bin/tar" <<'EOF'
#!/bin/sh
printf 'tar\n' >>"$TEST_EVENT_LOG"
exec "$REAL_TAR" "$@"
EOF

cat >"$test_bin/install" <<'EOF'
#!/bin/sh
printf 'install\n' >>"$TEST_EVENT_LOG"
if test "$TEST_INSTALL_SIGNAL" = 1; then
    kill -TERM "$PPID"
    exit 1
fi
test "$TEST_INSTALL_FAIL" != 1 || exit 1
exec "$REAL_INSTALL" "$@"
EOF

cat >"$test_bin/mv" <<'EOF'
#!/bin/sh
printf 'mv\n' >>"$TEST_EVENT_LOG"
test "$TEST_MOVE_FAIL" != 1 || exit 1
exec "$REAL_MV" "$@"
EOF

chmod +x \
    "$test_bin/uname" \
    "$test_bin/getconf" \
    "$test_bin/ldd" \
    "$test_bin/mktemp" \
    "$test_bin/curl" \
    "$test_bin/wget" \
    "$test_bin/sha256sum" \
    "$test_bin/tar" \
    "$test_bin/install" \
    "$test_bin/mv"
for name in uname getconf ldd mktemp tar install mv sha256sum; do
    for directory in "$wget_bin" "$no_download_bin" "$no_sha_bin"; do
        if test "$directory:$name" = "$no_sha_bin:sha256sum"; then
            continue
        fi
        rm -f "$directory/$name"
        cp "$test_bin/$name" "$directory/$name"
    done
done
cp "$test_bin/wget" "$wget_bin/wget"
cp "$test_bin/curl" "$test_bin/wget" "$no_sha_bin/"

cat >"$root/archive/keyhold" <<'EOF'
#!/bin/sh
printf 'candidate\n' >>"$TEST_EVENT_LOG"
test "${TEST_CANDIDATE_EXIT:-0}" -eq 0 || exit "$TEST_CANDIDATE_EXIT"
printf 'keyhold %s\n' "$TEST_CANDIDATE_VERSION"
EOF
chmod +x "$root/archive/keyhold"
printf 'release readme\n' >"$root/archive/README.md"
printf 'release licence\n' >"$root/archive/LICENSE.txt"

targets='x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl'
for target in $targets; do
    archive="keyhold-v0.2.0-$target.tar.gz"
    "$REAL_TAR" -czf "$release_dir/$archive" -C "$root/archive" keyhold README.md LICENSE.txt
    (cd "$release_dir" && "$REAL_SHA256SUM" "$archive" >"$archive.sha256")
done
"$REAL_TAR" -czf "$release_dir/missing.tar.gz" -C "$root/empty" .
TEST_LATEST_URL=https://github.com/seapagan/keyhold/releases/tag/v0.2.0
TEST_RELEASE_DIR=$release_dir
TEST_DOWNLOAD_LOG=$root/downloads.log
TEST_DOWNLOADER_LOG=$root/downloaders.log
TEST_EVENT_LOG=$root/events.log
TEST_TMP_PARENT=$root/installer-tmp
TEST_MKTEMP_COUNTER=$root/mktemp-counter
TEST_MKTEMP_LAST=$root/mktemp-last
TEST_STAGE_COUNTER=$root/stage-counter
TEST_STAGE_LAST=$root/stage-last
export TEST_LATEST_URL TEST_RELEASE_DIR TEST_DOWNLOAD_LOG TEST_DOWNLOADER_LOG
export TEST_EVENT_LOG TEST_TMP_PARENT TEST_MKTEMP_COUNTER TEST_MKTEMP_LAST
export TEST_STAGE_COUNTER TEST_STAGE_LAST

printf '0\n' >"$TEST_MKTEMP_COUNTER"
printf '0\n' >"$TEST_STAGE_COUNTER"
passes=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    cat "$root/output" >&2 || :
    exit 1
}

pass() { passes=$((passes + 1)); }

reset_env() {
    KEYHOLD_VERSION=v0.2.0
    KEYHOLD_INSTALL_DIR=$root/install
    KEYHOLD_LIBC=
    XDG_BIN_HOME=
    HOME=$root/home
    TEST_OS=Linux
    TEST_ARCH=x86_64
    TEST_BIN=$test_bin
    TEST_GETCONF_KIND=glibc
    TEST_LDD_KIND=glibc
    TEST_GLIBC_VERSION=2.28
    TEST_CANDIDATE_VERSION=0.2.0
    TEST_CANDIDATE_EXIT=0
    TEST_LATEST_URL=https://github.com/seapagan/keyhold/releases/tag/v0.2.0
    TEST_INSTALL_FAIL=0
    TEST_INSTALL_SIGNAL=0
    TEST_MOVE_FAIL=0
    TEST_STAGE_FAIL=0
    : >"$TEST_DOWNLOAD_LOG"
    : >"$TEST_DOWNLOADER_LOG"
    : >"$TEST_EVENT_LOG"
    rm -rf "$KEYHOLD_INSTALL_DIR"
    export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR KEYHOLD_LIBC XDG_BIN_HOME HOME
    export TEST_OS TEST_ARCH TEST_BIN TEST_GETCONF_KIND TEST_LDD_KIND
    export TEST_GLIBC_VERSION TEST_CANDIDATE_VERSION TEST_CANDIDATE_EXIT TEST_LATEST_URL
    export TEST_INSTALL_FAIL TEST_INSTALL_SIGNAL TEST_MOVE_FAIL TEST_STAGE_FAIL
}

run_install() {
    env PATH="$TEST_BIN" /bin/sh ./install.sh >"$root/output" 2>&1
}

assert_fails() {
    message=$1
    if run_install; then fail "$message"; fi
}

assert_output() { grep -Fq "$1" "$root/output" || fail "missing output: $1"; }

assert_no_output() {
    if grep -Fq "$1" "$root/output"; then fail "unexpected output: $1"; fi
}

assert_downloaded() {
    grep -Fxq "https://github.com/seapagan/keyhold/releases/download/v0.2.0/$1" "$TEST_DOWNLOAD_LOG" || fail "asset was not downloaded: $1"
}

assert_target() {
    assert_downloaded "keyhold-v0.2.0-$1.tar.gz"
    assert_downloaded "keyhold-v0.2.0-$1.tar.gz.sha256"
}

assert_old_binary() {
    test "$(cat "$KEYHOLD_INSTALL_DIR/keyhold")" = 'old keyhold' || fail 'existing keyhold changed after failure'
}

assert_no_binary() { test ! -e "$KEYHOLD_INSTALL_DIR/keyhold" || fail 'failed installation created a final binary'; }

assert_tmp_cleaned() {
    temporary_directory=$(cat "$TEST_MKTEMP_LAST")
    test ! -e "$temporary_directory" || fail 'temporary directory was not removed'
}

for case_data in 'x86_64:x86_64-unknown-linux-gnu' 'amd64:x86_64-unknown-linux-gnu' 'aarch64:aarch64-unknown-linux-gnu' 'arm64:aarch64-unknown-linux-gnu'; do
    reset_env
    TEST_ARCH=${case_data%%:*}
    export TEST_ARCH
    run_install || fail "architecture $TEST_ARCH failed"
    assert_target "${case_data#*:}"
    pass
done

reset_env; TEST_OS=Darwin; export TEST_OS
assert_fails 'unsupported operating system succeeded'; assert_output 'unsupported platform: Darwin/x86_64'; pass
reset_env; TEST_ARCH=ppc64le; export TEST_ARCH
assert_fails 'unsupported architecture succeeded'; assert_output 'unsupported platform: Linux/ppc64le'; pass

for case_data in '2.39:gnu' '2.28:gnu' '2.27:musl' '1.17:musl'; do
    reset_env
    TEST_GLIBC_VERSION=${case_data%%:*}
    export TEST_GLIBC_VERSION
    run_install || fail "glibc $TEST_GLIBC_VERSION selection failed"
    assert_target "x86_64-unknown-linux-${case_data#*:}"
    if test "${case_data#*:}" = musl; then assert_output 'older than Keyhold minimum 2.28; using static musl build'; fi
    pass
done

reset_env; TEST_GETCONF_KIND=unavailable; TEST_LDD_KIND=musl; export TEST_GETCONF_KIND TEST_LDD_KIND
run_install || fail 'musl detection failed'; assert_target x86_64-unknown-linux-musl; pass
reset_env; TEST_GETCONF_KIND=unavailable; TEST_LDD_KIND=glibc; TEST_GLIBC_VERSION=2.39; export TEST_GETCONF_KIND TEST_LDD_KIND TEST_GLIBC_VERSION
run_install || fail 'ldd glibc fallback failed'; assert_target x86_64-unknown-linux-gnu; pass
reset_env; TEST_GETCONF_KIND=unavailable; TEST_LDD_KIND=unavailable; export TEST_GETCONF_KIND TEST_LDD_KIND
assert_fails 'unknown libc succeeded'; assert_output 'unable to detect libc'; assert_output 'KEYHOLD_LIBC=gnu or KEYHOLD_LIBC=musl'; pass
reset_env; TEST_GETCONF_KIND=malformed; TEST_LDD_KIND=malformed; export TEST_GETCONF_KIND TEST_LDD_KIND
assert_fails 'malformed libc data succeeded'; assert_output 'unable to detect libc'; pass

for libc in gnu musl; do
    reset_env
    KEYHOLD_LIBC=$libc; TEST_GETCONF_KIND=unavailable; TEST_LDD_KIND=unavailable
    export KEYHOLD_LIBC TEST_GETCONF_KIND TEST_LDD_KIND
    run_install || fail "$libc override failed"
    assert_target "x86_64-unknown-linux-$libc"
    pass
done

reset_env
TEST_ARCH=aarch64; KEYHOLD_LIBC=musl
export TEST_ARCH KEYHOLD_LIBC
run_install || fail 'aarch64 musl target failed'
assert_target aarch64-unknown-linux-musl; pass

reset_env; KEYHOLD_LIBC=other; export KEYHOLD_LIBC
assert_fails 'invalid libc override succeeded'; assert_output 'KEYHOLD_LIBC must be gnu or musl'; pass

reset_env
KEYHOLD_LIBC=gnu; TEST_GLIBC_VERSION=2.17; TEST_CANDIDATE_EXIT=127
mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
export KEYHOLD_LIBC TEST_GLIBC_VERSION TEST_CANDIDATE_EXIT
assert_fails 'incompatible forced GNU candidate succeeded'; assert_old_binary; pass

reset_env
run_install || fail 'target URLs failed'; assert_target x86_64-unknown-linux-gnu
test "$(wc -l <"$TEST_DOWNLOAD_LOG")" -eq 2 || fail 'wrong download count'; pass

reset_env
run_install || fail 'valid checksum failed'; grep -Fxq sha256sum "$TEST_EVENT_LOG" || fail 'sha256sum did not run'; pass

for mode in bad malformed wrong-name external-file; do
    reset_env
    archive=keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
    sidecar=$release_dir/$archive.sha256
    backup=$root/sidecar-backup
    cp "$sidecar" "$backup"
    case "$mode" in
        bad) printf '%064d  %s\n' 0 "$archive" >"$sidecar" ;;
        malformed) printf 'malformed\n' >"$sidecar" ;;
        wrong-name) sed 's/x86_64-unknown-linux-gnu/aarch64-unknown-linux-gnu/' "$backup" >"$sidecar" ;;
        external-file) "$REAL_SHA256SUM" "$root/archive/keyhold" >"$sidecar" ;;
    esac
    mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    assert_fails "$mode checksum succeeded"; assert_output 'checksum verification failed'; assert_old_binary
    if grep -Eq '^(tar|install|mv)$' "$TEST_EVENT_LOG"; then fail 'checksum failure reached extraction or installation'; fi
    cp "$backup" "$sidecar"
    pass
done

reset_env
archive=keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
sidecar=$release_dir/$archive.sha256
backup=$root/sidecar-backup
cp "$sidecar" "$backup"
printf '%064d  %s\n' 0 "$archive" >"$sidecar"
assert_fails 'bad checksum created no-install case succeeded'
assert_no_binary
cp "$backup" "$sidecar"; pass

reset_env; TEST_BIN=$no_sha_bin; export TEST_BIN
assert_fails 'missing sha256sum succeeded'; assert_output 'sha256sum is required'; assert_no_binary; pass

reset_env; TEST_CANDIDATE_EXIT=1; mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"; export TEST_CANDIDATE_EXIT
assert_fails 'candidate non-zero exit succeeded'; assert_old_binary; pass
reset_env; TEST_CANDIDATE_VERSION=9.9.9; export TEST_CANDIDATE_VERSION
assert_fails 'wrong candidate version succeeded'; assert_output 'reported version does not match v0.2.0'; assert_no_binary; pass

reset_env
bad_archive=$root/bad-archive; mkdir "$bad_archive"
printf '#!/missing/interpreter\n' >"$bad_archive/keyhold"; chmod +x "$bad_archive/keyhold"
cp "$root/archive/README.md" "$root/archive/LICENSE.txt" "$bad_archive/"
archive=keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
"$REAL_TAR" -czf "$release_dir/$archive" -C "$bad_archive" keyhold README.md LICENSE.txt
(cd "$release_dir" && "$REAL_SHA256SUM" "$archive" >"$archive.sha256")
assert_fails 'unexecutable candidate succeeded'; assert_output 'candidate failed --version validation'; assert_no_binary
"$REAL_TAR" -czf "$release_dir/$archive" -C "$root/archive" keyhold README.md LICENSE.txt
(cd "$release_dir" && "$REAL_SHA256SUM" "$archive" >"$archive.sha256"); pass

reset_env; KEYHOLD_INSTALL_DIR=$root/success-bin; export KEYHOLD_INSTALL_DIR
run_install || fail 'successful replacement failed'
test -x "$KEYHOLD_INSTALL_DIR/keyhold" || fail 'installed binary is not executable'
test "$("$KEYHOLD_INSTALL_DIR/keyhold" --version)" = 'keyhold 0.2.0' || fail 'installed candidate is wrong'
test ! -e "$KEYHOLD_INSTALL_DIR/README.md" || fail 'README was installed'
test ! -e "$KEYHOLD_INSTALL_DIR/LICENSE.txt" || fail 'license was installed'; pass

for failure in stage install move; do
    reset_env
    mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    case "$failure" in stage) TEST_STAGE_FAIL=1 ;; install) TEST_INSTALL_FAIL=1 ;; move) TEST_MOVE_FAIL=1 ;; esac
    export TEST_STAGE_FAIL TEST_INSTALL_FAIL TEST_MOVE_FAIL
    assert_fails "$failure failure succeeded"; assert_old_binary
    test -z "$(find "$KEYHOLD_INSTALL_DIR" -name '.keyhold.*' -print)" || fail "$failure left a destination staging file"
    pass
done

reset_env
mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
TEST_INSTALL_SIGNAL=1; export TEST_INSTALL_SIGNAL
assert_fails 'interrupted install succeeded'; assert_old_binary
test -z "$(find "$KEYHOLD_INSTALL_DIR" -name '.keyhold.*' -print)" || fail 'interrupt left a destination staging file'
pass

reset_env
mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
run_install || fail 'replacement of existing binary failed'
test "$("$KEYHOLD_INSTALL_DIR/keyhold" --version)" = 'keyhold 0.2.0' || fail 'existing binary was not replaced'; pass

reset_env; KEYHOLD_VERSION=; export KEYHOLD_VERSION
run_install || fail 'latest-release lookup failed'
grep -Fxq 'https://github.com/seapagan/keyhold/releases/latest' "$TEST_DOWNLOAD_LOG" || fail 'GitHub latest-release redirect was not used'
if grep -Fq 'api.github.com' "$TEST_DOWNLOAD_LOG"; then fail 'latest lookup used api.github.com'; fi
assert_target x86_64-unknown-linux-gnu; pass
reset_env; KEYHOLD_VERSION=v0.2.0; export KEYHOLD_VERSION
run_install || fail 'explicit version failed'
if grep -Fq '/releases/latest' "$TEST_DOWNLOAD_LOG"; then fail 'explicit version queried latest release'; fi
pass

reset_env; KEYHOLD_VERSION=; TEST_LATEST_URL=https://github.com/seapagan/keyhold/releases/tag/not-a-version
export KEYHOLD_VERSION TEST_LATEST_URL
assert_fails 'malformed latest-release redirect succeeded'
assert_output 'latest release redirect did not resolve to a usable release tag'
if grep -Fq '/releases/download/' "$TEST_DOWNLOAD_LOG"; then fail 'malformed latest redirect attempted an asset download'; fi
pass

for install_state in existing fresh; do
    reset_env
    KEYHOLD_VERSION=v0.1.0; export KEYHOLD_VERSION
    if test "$install_state" = existing; then
        mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    fi
    assert_fails "explicit old version with missing archive succeeded ($install_state)"
    assert_output 'could not download required release asset: keyhold-v0.1.0-x86_64-unknown-linux-gnu.tar.gz'
    assert_output 'If this is an older release, it may predate the current GNU/musl artifact layout.'
    assert_output 'https://github.com/seapagan/keyhold/releases/tag/v0.1.0'
    if test "$install_state" = existing; then assert_old_binary; else assert_no_binary; fi
    pass
done

old_archive=keyhold-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cp "$release_dir/keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz" "$release_dir/$old_archive"
for install_state in existing fresh; do
    reset_env
    KEYHOLD_VERSION=v0.1.0; export KEYHOLD_VERSION
    if test "$install_state" = existing; then
        mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    fi
    assert_fails "explicit old version with missing checksum succeeded ($install_state)"
    assert_output "could not download required checksum asset: $old_archive.sha256"
    assert_output 'If this is an older release, it may predate checksum-backed installer support.'
    assert_output 'https://github.com/seapagan/keyhold/releases/tag/v0.1.0'
    if test "$install_state" = existing; then assert_old_binary; else assert_no_binary; fi
    pass
done
rm "$release_dir/$old_archive"

current_archive=keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
mv "$release_dir/$current_archive" "$root/current-archive"
for install_state in existing fresh; do
    reset_env
    KEYHOLD_VERSION=; export KEYHOLD_VERSION
    if test "$install_state" = existing; then
        mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    fi
    assert_fails "latest release with missing archive succeeded ($install_state)"
    assert_output "could not download required release asset: $current_archive"
    assert_no_output 'If this is an older release'
    if test "$install_state" = existing; then assert_old_binary; else assert_no_binary; fi
    pass
done
mv "$root/current-archive" "$release_dir/$current_archive"

mv "$release_dir/$current_archive.sha256" "$root/current-checksum"
for install_state in existing fresh; do
    reset_env
    KEYHOLD_VERSION=; export KEYHOLD_VERSION
    if test "$install_state" = existing; then
        mkdir -p "$KEYHOLD_INSTALL_DIR"; printf 'old keyhold\n' >"$KEYHOLD_INSTALL_DIR/keyhold"
    fi
    assert_fails "latest release with missing checksum succeeded ($install_state)"
    assert_output "could not download required checksum asset: $current_archive.sha256"
    assert_no_output 'If this is an older release'
    if test "$install_state" = existing; then assert_old_binary; else assert_no_binary; fi
    pass
done
mv "$root/current-checksum" "$release_dir/$current_archive.sha256"

reset_env
KEYHOLD_VERSION=; export KEYHOLD_VERSION
run_install || fail 'curl latest-resolution path failed'; grep -Fxq curl "$TEST_DOWNLOADER_LOG" || fail 'curl was not preferred'; pass
reset_env; TEST_BIN=$wget_bin; export TEST_BIN
KEYHOLD_VERSION=; export KEYHOLD_VERSION
run_install || fail 'wget latest-resolution fallback failed'; grep -Fxq wget "$TEST_DOWNLOADER_LOG" || fail 'wget did not run'; pass
reset_env; TEST_BIN=$no_download_bin; export TEST_BIN
assert_fails 'missing downloader succeeded'; assert_output 'curl or wget is required'; assert_tmp_cleaned; pass

reset_env; KEYHOLD_INSTALL_DIR=$root/'explicit bin'; XDG_BIN_HOME=$root/ignored-xdg; HOME=$root/ignored-home; export KEYHOLD_INSTALL_DIR XDG_BIN_HOME HOME
run_install || fail 'explicit install directory failed'; test -x "$KEYHOLD_INSTALL_DIR/keyhold" || fail 'explicit install directory was ignored'; test ! -e "$XDG_BIN_HOME/keyhold" || fail 'XDG overrode explicit directory'; pass
reset_env; XDG_BIN_HOME=$root/'xdg bin'; KEYHOLD_INSTALL_DIR=; export XDG_BIN_HOME KEYHOLD_INSTALL_DIR
run_install || fail 'XDG install directory failed'; test -x "$XDG_BIN_HOME/keyhold" || fail 'XDG directory was ignored'; pass
reset_env; HOME=$root/'default home'; KEYHOLD_INSTALL_DIR=; export HOME KEYHOLD_INSTALL_DIR
run_install || fail 'default install directory failed'; test -x "$HOME/.local/bin/keyhold" || fail 'default directory was ignored'; pass
reset_env
unset KEYHOLD_INSTALL_DIR XDG_BIN_HOME HOME
assert_fails 'missing install directory inputs succeeded'
assert_output 'no install directory could be determined; set KEYHOLD_INSTALL_DIR'
test ! -s "$TEST_DOWNLOAD_LOG" || fail 'missing install directory inputs attempted a release download'
pass

reset_env
archive=keyhold-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
cp "$release_dir/missing.tar.gz" "$release_dir/$archive"
(cd "$release_dir" && "$REAL_SHA256SUM" "$archive" >"$archive.sha256")
assert_fails 'archive without keyhold succeeded'; assert_output 'release archive is missing keyhold'; assert_no_binary
"$REAL_TAR" -czf "$release_dir/$archive" -C "$root/archive" keyhold README.md LICENSE.txt
(cd "$release_dir" && "$REAL_SHA256SUM" "$archive" >"$archive.sha256"); pass

reset_env; KEYHOLD_INSTALL_DIR=$root/not-on-path; export KEYHOLD_INSTALL_DIR
run_install || fail 'PATH warning setup failed'; assert_output 'add it to PATH'; pass
reset_env; KEYHOLD_INSTALL_DIR=$root/near-path; TEST_BIN=$test_bin:$KEYHOLD_INSTALL_DIR-extra; export KEYHOLD_INSTALL_DIR TEST_BIN
run_install || fail 'near PATH setup failed'; assert_output 'add it to PATH'; pass
reset_env; KEYHOLD_INSTALL_DIR=$root/'on path'; TEST_BIN=$test_bin:$KEYHOLD_INSTALL_DIR; export KEYHOLD_INSTALL_DIR TEST_BIN
run_install || fail 'exact PATH setup failed'
if grep -Fq 'add it to PATH' "$root/output"; then fail 'exact PATH component produced a warning'; fi
assert_tmp_cleaned; pass

printf 'Unix installer tests passed: %s cases.\n' "$passes"
