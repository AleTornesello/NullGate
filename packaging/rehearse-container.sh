#!/bin/sh
set -eu
cd /artifacts
sha256sum -c SHA256SUMS
useradd --create-home --uid 1001 --shell /bin/sh release-user
install -d -o release-user -g release-user -m 0700 /home/release-user/unpacked
tar -xzf nullgate-*-x86_64-unknown-linux-gnu.tar.gz --strip-components=1 -C /home/release-user/unpacked
runuser -u release-user -- env HOME=/home/release-user python3 /home/release-user/unpacked/install-user.py
install -m 0644 /source/scripts/release_smoke.py /home/release-user/release-smoke.py
runuser -u release-user -- env HOME=/home/release-user python3 /home/release-user/release-smoke.py --mode local --binary /home/release-user/.local/bin/nullgate --config /home/release-user/.config/nullgate/nullgate.toml --data /home/release-user/.local/share/nullgate --bundle /home/release-user/unpacked
dpkg -i nullgate_*_amd64.deb
test "$(stat -c '%U:%G:%a' /etc/nullgate/nullgate.toml)" = 'root:nullgate:640'
test "$(stat -c '%U:%G:%a' /var/lib/nullgate)" = 'nullgate:nullgate:700'
python3 /source/scripts/release_smoke.py --mode dedicated --disposable-container --binary /usr/bin/nullgate --config /etc/nullgate/nullgate.toml --data /var/lib/nullgate
before=$(sha256sum /etc/nullgate/nullgate.toml /var/lib/nullgate/inspection-ca/material.bin)
dpkg --force-confold -i nullgate_*_amd64.deb
after=$(sha256sum /etc/nullgate/nullgate.toml /var/lib/nullgate/inspection-ca/material.bin)
test "$before" = "$after"
dpkg -r nullgate
test -f /etc/nullgate/nullgate.toml
test -f /var/lib/nullgate/inspection-ca/material.bin
printf '%s\n' '{"result":"passed","mode":"debian-reinstall-removal","state_retained":true}'
