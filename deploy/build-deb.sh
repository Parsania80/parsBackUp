#!/usr/bin/env bash
# Package supplied release bytes; never implicitly build against the host runtime.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# < 1 || $# > 3 )); then
    echo 'usage: deploy/build-deb.sh RELEASE_BINARY [OUTPUT_DIRECTORY] [VERSION]' >&2
    exit 2
fi
binary=$(realpath "$1")
output=$(realpath -m "${2:-$repo_root/target/packages}")
version=${3:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -1)~fixture.1}
dpkg --validate-version "$version"
[[ $(dpkg --print-architecture) == amd64 ]] || { echo 'only amd64 is supported' >&2; exit 1; }
readelf -h "$binary" | grep -q 'Advanced Micro Devices X86-64'
[[ -x $binary ]] || { echo 'supplied binary is not executable' >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" show -s --format=%ct HEAD)}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || { echo 'invalid SOURCE_DATE_EPOCH' >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/debian" "$stage/root/DEBIAN" "$stage/root/usr/bin" \
    "$stage/root/usr/lib/systemd/system" "$stage/root/usr/share/doc/backupctl/examples"
cat > "$stage/debian/control" <<'EOF'
Source: backupctl
Section: admin
Priority: optional
Maintainer: backupctl project <backupctl@localhost>

Package: backupctl
Architecture: amd64
Description: Synthetic PostgreSQL backup and recovery CLI
EOF
deps=$(cd "$stage" && dpkg-shlibdeps -O -e"$binary")
deps=${deps#shlibs:Depends=}
cat > "$stage/root/DEBIAN/control" <<EOF
Package: backupctl
Version: $version
Section: admin
Priority: optional
Architecture: amd64
Maintainer: backupctl project <backupctl@localhost>
Depends: adduser, systemd (>= 249), $deps
Recommends: postgresql-client
Description: Synthetic PostgreSQL backup and recovery CLI
 Signed encrypted local fixture backups with explicit recovery plans.
 Production operations remain disabled pending release acceptance.
EOF
install -m 755 "$binary" "$stage/root/usr/bin/backupctl"
install -m 644 "$repo_root"/deploy/systemd/* "$stage/root/usr/lib/systemd/system/"
install -m 755 "$repo_root"/deploy/debian/* "$stage/root/DEBIAN/"
install -m 644 "$repo_root/deploy/writer.example.toml" "$stage/root/usr/share/doc/backupctl/examples/"
install -m 644 "$repo_root/docs/development/h03-systemd-package.md" "$stage/root/usr/share/doc/backupctl/"
find "$stage/root" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"
mkdir -p "$output"
dpkg-deb --root-owner-group --uniform-compression -Zxz -z6 --build "$stage/root" "$output/backupctl_${version}_amd64.deb"
