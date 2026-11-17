#!/bin/sh
set -eu
# Compiler, native tools and libc come only from the pinned image. No apt/network step.
dpkg-query -W -f='${Package}=${Version}\n' | LC_ALL=C sort > /out/builder-packages.txt
chmod a+w /usr/local/cargo
exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_GID" --clear-groups sh -c '
set -eu
export RUSTUP_TOOLCHAIN=1.99.1-x86_64-unknown-linux-gnu
export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR=/out/target CARGO_INCREMENTAL=0 TZ=UTC LC_ALL=C
export RUSTFLAGS="--remap-path-prefix=/src=/usr/src/nullgate -C target-cpu=x86-64"
export CFLAGS="-ffile-prefix-map=/src=/usr/src/nullgate"
cd /src
cargo build --release --locked --frozen --target x86_64-unknown-linux-gnu -p nullgate
cp /out/target/x86_64-unknown-linux-gnu/release/nullgate /out/nullgate
/out/nullgate --version > /out/version.txt
readelf --version-info /out/nullgate > /out/elf-versions.txt
cargo metadata --locked --offline --filter-platform x86_64-unknown-linux-gnu --format-version 1 > /out/cargo-metadata.json
rustc -Vv > /out/rustc.txt
cargo test --release --locked --frozen --target x86_64-unknown-linux-gnu -p nullgate --test end_to_end --no-run
mkdir -p /out/tools
printf "#!/bin/sh\nkill \"\$@\"\n" > /out/tools/kill
chmod +x /out/tools/kill
export PATH=/out/tools:$PATH NULLGATE_E2E_BINARY=/out/nullgate NULLGATE_E2E_ARTIFACTS=/out/e2e-artifacts
harness=$(find /out/target/x86_64-unknown-linux-gnu/release/deps -maxdepth 1 -type f -name "end_to_end-*" -executable)
[ -n "$harness" ]
"$harness" > /out/e2e-results.txt
sysroot=$(rustc --print sysroot)
test -d "$sysroot/share/doc/rust/licenses"
cp -r "$sysroot/share/doc/rust/licenses" /out/rust-licenses
cp "$sysroot/share/doc/rust/COPYRIGHT"*.html /out/rust-licenses/
'
