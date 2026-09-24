#!/bin/sh
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' 0
trap 'exit 1' 1 2 3 15

mkdir -p "$root/bin" "$root/wget-bin" "$root/no-download-bin" \
    "$root/archive" "$root/empty" "$root/installer-tmp"
for command in cat chmod cp grep gzip head install mkdir rm sed tar; do
    path=$(command -v "$command")
    ln -s "$path" "$root/bin/$command"
    ln -s "$path" "$root/wget-bin/$command"
    ln -s "$path" "$root/no-download-bin/$command"
done

TEST_REAL_UNAME=$(command -v uname)
export TEST_REAL_UNAME
cat > "$root/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "$TEST_OS" ;;
    -m) printf '%s\n' "$TEST_ARCH" ;;
    *) exec "$TEST_REAL_UNAME" "$@" ;;
esac
EOF
cp "$root/bin/uname" "$root/wget-bin/uname"
cp "$root/bin/uname" "$root/no-download-bin/uname"

TEST_MKTEMP_COUNTER=$root/mktemp-counter
TEST_MKTEMP_LAST=$root/mktemp-last
printf '0\n' > "$TEST_MKTEMP_COUNTER"
export TEST_MKTEMP_COUNTER TEST_MKTEMP_LAST
cat > "$root/bin/mktemp" <<'EOF'
#!/bin/sh
count=$(cat "$TEST_MKTEMP_COUNTER")
count=$((count + 1))
printf '%s\n' "$count" > "$TEST_MKTEMP_COUNTER"
directory="$TEST_TMP_PARENT/run-$count"
mkdir "$directory"
printf '%s\n' "$directory" > "$TEST_MKTEMP_LAST"
printf '%s\n' "$directory"
EOF
cp "$root/bin/mktemp" "$root/wget-bin/mktemp"
cp "$root/bin/mktemp" "$root/no-download-bin/mktemp"

cat > "$root/bin/curl" <<'EOF'
#!/bin/sh
url=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) destination=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >> "$TEST_LOG"
printf 'curl\n' >> "$TEST_DOWNLOADER_LOG"
case "$url" in
    */releases/latest) cp "$TEST_API" "$destination" ;;
    */releases/download/*) cp "$TEST_ARCHIVE" "$destination" ;;
    *) exit 1 ;;
esac
EOF

cat > "$root/wget-bin/wget" <<'EOF'
#!/bin/sh
url=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -qO) destination=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s\n' "$url" >> "$TEST_LOG"
printf 'wget\n' >> "$TEST_DOWNLOADER_LOG"
case "$url" in
    */releases/latest) cp "$TEST_API" "$destination" ;;
    */releases/download/*) cp "$TEST_ARCHIVE" "$destination" ;;
    *) exit 1 ;;
esac
EOF
cp "$root/wget-bin/wget" "$root/bin/wget"
chmod +x "$root/bin/uname" "$root/bin/mktemp" "$root/bin/curl" \
    "$root/bin/wget" "$root/wget-bin/uname" "$root/wget-bin/mktemp" \
    "$root/wget-bin/wget" "$root/no-download-bin/uname" \
    "$root/no-download-bin/mktemp"

printf 'new keyhold\n' > "$root/archive/keyhold"
printf 'release readme\n' > "$root/archive/README.md"
printf 'release licence\n' > "$root/archive/LICENSE.txt"
tar -czf "$root/release.tar.gz" -C "$root/archive" \
    keyhold README.md LICENSE.txt
tar -czf "$root/missing.tar.gz" -C "$root/empty" .
printf '{"tag_name": "v0.2.0"}\n' > "$root/latest.json"

TEST_ARCHIVE=$root/release.tar.gz
TEST_API=$root/latest.json
TEST_LOG=$root/downloads.log
TEST_DOWNLOADER_LOG=$root/downloaders.log
TEST_TMP_PARENT=$root/installer-tmp
export TEST_ARCHIVE TEST_API TEST_LOG TEST_DOWNLOADER_LOG TEST_TMP_PARENT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

reset_env() {
    KEYHOLD_VERSION=
    KEYHOLD_INSTALL_DIR=
    XDG_BIN_HOME=
    HOME="$root/home"
    TEST_OS=Linux
    TEST_ARCH=x86_64
    TEST_BIN=$root/bin
    TEST_ARCHIVE=$root/release.tar.gz
    export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR XDG_BIN_HOME HOME
    export TEST_OS TEST_ARCH TEST_BIN TEST_ARCHIVE
}

run_install() {
    : > "$TEST_LOG"
    : > "$TEST_DOWNLOADER_LOG"
    env PATH="$TEST_BIN" /bin/sh ./install.sh > "$root/output" 2>&1
}

assert_tmp_cleaned() {
    temporary_directory=$(cat "$TEST_MKTEMP_LAST")
    test ! -e "$temporary_directory" || fail "temporary directory was not removed"
}

assert_asset() {
    expected="keyhold-$1-$2.tar.gz"
    expected_url="https://github.com/seapagan/keyhold/releases/download/$1/$expected"
    grep -Fxq "$expected_url" "$TEST_LOG" || \
        fail "wrong release asset: $expected"
}

assert_target() {
    reset_env
    TEST_OS=$1
    TEST_ARCH=$2
    KEYHOLD_VERSION=v0.2.0
    KEYHOLD_INSTALL_DIR="$root/targets/$1-$2"
    export TEST_OS TEST_ARCH KEYHOLD_VERSION KEYHOLD_INSTALL_DIR
    run_install
    assert_asset v0.2.0 "$3"
}

assert_target Linux x86_64 x86_64-unknown-linux-gnu
assert_target Linux amd64 x86_64-unknown-linux-gnu
assert_target Linux aarch64 aarch64-unknown-linux-gnu
assert_target Linux arm64 aarch64-unknown-linux-gnu

reset_env
TEST_OS=Darwin
KEYHOLD_VERSION=v0.2.0
export TEST_OS KEYHOLD_VERSION
if run_install; then
    fail 'Darwin was accepted'
fi
grep -q 'unsupported platform' "$root/output" || \
    fail 'Darwin failure did not explain unsupported platform'

reset_env
TEST_ARCH=ppc64le
KEYHOLD_VERSION=v0.2.0
export TEST_ARCH KEYHOLD_VERSION
if run_install; then
    fail 'unknown Linux architecture was accepted'
fi
grep -q 'unsupported platform' "$root/output" || \
    fail 'unknown architecture failure did not explain unsupported platform'

reset_env
KEYHOLD_VERSION=v9.8.7
KEYHOLD_INSTALL_DIR="$root/explicit-version"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR
run_install
assert_asset v9.8.7 x86_64-unknown-linux-gnu
assert_tmp_cleaned
if grep -q '/releases/latest' "$TEST_LOG"; then
    fail 'explicit KEYHOLD_VERSION queried the latest-release endpoint'
fi

reset_env
KEYHOLD_INSTALL_DIR="$root/latest-version"
export KEYHOLD_INSTALL_DIR
run_install
grep -q '/releases/latest' "$TEST_LOG" || \
    fail 'unset KEYHOLD_VERSION did not query the latest-release endpoint'
assert_asset v0.2.0 x86_64-unknown-linux-gnu

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/curl-install"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR
run_install
grep -Fxq curl "$TEST_DOWNLOADER_LOG" || fail 'curl path did not run curl'
if grep -Fxq wget "$TEST_DOWNLOADER_LOG"; then
    fail 'wget ran even though curl was available'
fi

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/wget-install"
TEST_BIN=$root/wget-bin
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR TEST_BIN
run_install
test -x "$KEYHOLD_INSTALL_DIR/keyhold" || fail 'wget fallback did not install keyhold'
grep -Fxq wget "$TEST_DOWNLOADER_LOG" || fail 'wget fallback did not run wget'

reset_env
KEYHOLD_VERSION=v0.2.0
TEST_BIN=$root/no-download-bin
export KEYHOLD_VERSION TEST_BIN
if run_install; then
    fail 'installation without curl or wget succeeded'
fi
grep -q 'curl or wget is required' "$root/output" || \
    fail 'missing downloader failure was unclear'
assert_tmp_cleaned

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/explicit bin"
XDG_BIN_HOME="$root/ignored-xdg"
HOME="$root/ignored-home"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR XDG_BIN_HOME HOME
mkdir -p "$KEYHOLD_INSTALL_DIR"
printf 'old keyhold\n' > "$KEYHOLD_INSTALL_DIR/keyhold"
run_install
grep -q '^new keyhold$' "$KEYHOLD_INSTALL_DIR/keyhold" || \
    fail 'existing keyhold was not replaced'
test -x "$KEYHOLD_INSTALL_DIR/keyhold" || fail 'installed keyhold is not executable'
test ! -e "$XDG_BIN_HOME/keyhold" || fail 'XDG_BIN_HOME overrode KEYHOLD_INSTALL_DIR'
test ! -e "$KEYHOLD_INSTALL_DIR/README.md" || fail 'README.md was installed'
test ! -e "$KEYHOLD_INSTALL_DIR/LICENSE.txt" || fail 'LICENSE.txt was installed'

reset_env
KEYHOLD_VERSION=v0.2.0
XDG_BIN_HOME="$root/xdg bin"
export KEYHOLD_VERSION XDG_BIN_HOME
run_install
test -x "$XDG_BIN_HOME/keyhold" || fail 'XDG_BIN_HOME was not used'

reset_env
KEYHOLD_VERSION=v0.2.0
HOME="$root/default home"
export KEYHOLD_VERSION HOME
run_install
test -x "$HOME/.local/bin/keyhold" || fail 'HOME/.local/bin was not used'

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/missing-keyhold"
TEST_ARCHIVE=$root/missing.tar.gz
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR TEST_ARCHIVE
if run_install; then
    fail 'archive missing keyhold was accepted'
fi
grep -q 'archive is missing keyhold' "$root/output" || \
    fail 'missing keyhold failure was unclear'
assert_tmp_cleaned

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/not-on-path"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR
run_install
grep -q 'add it to PATH' "$root/output" || fail 'missing PATH warning'

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/near-path"
TEST_BIN="$root/bin:$KEYHOLD_INSTALL_DIR-extra"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR TEST_BIN
run_install
grep -q 'add it to PATH' "$root/output" || \
    fail 'near-match PATH component suppressed the warning'

reset_env
KEYHOLD_VERSION=v0.2.0
KEYHOLD_INSTALL_DIR="$root/on path"
TEST_BIN="$root/bin:$KEYHOLD_INSTALL_DIR"
export KEYHOLD_VERSION KEYHOLD_INSTALL_DIR TEST_BIN
run_install
if grep -q 'add it to PATH' "$root/output"; then
    fail 'PATH warning appeared for an exact PATH component'
fi

printf 'Unix installer tests passed.\n'
