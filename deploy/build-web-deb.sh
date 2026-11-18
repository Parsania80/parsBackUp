#!/usr/bin/env bash
# Assemble the supplied release executable and Vite output on the build target.
set -euo pipefail
umask 022
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# != 4 )); then
    echo 'usage: deploy/build-web-deb.sh RELEASE_BINARY UI_DIST OUTPUT_DIRECTORY VERSION' >&2
    exit 2
fi
binary=$(realpath "$1")
dist=$(realpath "$2")
output=$(realpath -m "$3")
version=$4
dpkg --validate-version "$version"
[[ $(dpkg --print-architecture) == amd64 && -x $binary ]]
readelf -h "$binary" | grep -q 'Advanced Micro Devices X86-64'
[[ -f $dist/index.html && ! -L $dist/index.html && -d $dist/assets && ! -L $dist/assets ]]
[[ -z $(find "$dist/assets" ! -type d ! -type f -print -quit) ]]
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" show -s --format=%ct HEAD)}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]]

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
root="$stage/debian/backupctl-web"
share="$root/usr/share/backupctl-web"
www="$share/www"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/systemd/system" "$www" "$share/examples"
install -m 755 "$binary" "$root/usr/bin/backup-api"
install -m 644 "$dist/index.html" "$www/"
cp -R -- "$dist/assets" "$www/"
find "$www/assets" -type d -exec chmod 755 {} +
find "$www/assets" -type f -exec chmod 644 {} +
install -m 644 "$repo_root/deploy/systemd/backup-api.service" "$root/usr/lib/systemd/system/"
install -m 644 "$repo_root/deploy/nginx/backupctl-web.conf" "$share/examples/"
cat > "$stage/debian/control" <<'EOF'
Source: backupctl-web
Section: admin
Priority: optional
Maintainer: backupctl project <backupctl@localhost>

Package: backupctl-web
Architecture: amd64
Description: Fixture backup API and operator console
EOF
deps=$(cd "$stage" && dpkg-shlibdeps -O -edebian/backupctl-web/usr/bin/backup-api)
cat > "$root/DEBIAN/control" <<EOF
Package: backupctl-web
Version: $version
Section: admin
Priority: optional
Architecture: amd64
Maintainer: backupctl project <backupctl@localhost>
Depends: backupctl, nginx, systemd (>= 249), ${deps#shlibs:Depends=}
Description: Fixture backup API and operator console
 Installs the supervised local API and static console. TLS and activation
 require explicit configuration. Production backup operations are disabled.
EOF
find "$root" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"
mkdir -p "$output"
dpkg-deb --root-owner-group --uniform-compression -Zxz -z6 --build "$root" \
    "$output/backupctl-web_${version}_amd64.deb"
