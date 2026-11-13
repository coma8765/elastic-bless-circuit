set -eu
case "$(dpkg --print-architecture)" in
 amd64) xarch=64; tarch=amd64; xsha=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82 ;;
 arm64) xarch=arm64-v8a; tarch=arm64; xsha=64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be ;;
 *) exit 1;;
esac
# Hashes are locked to this release; version changes require an explicit hash update.
test "$XRAY_VERSION" = 26.11.9
mkdir -p /opt/bin /opt/share /tmp/xray /tmp/ts
curl --fail --location --retry 4 "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${xarch}.zip" -o /tmp/xray.zip
printf '%s  /tmp/xray.zip\n' "$xsha" | sha256sum -c -
unzip -q /tmp/xray.zip -d /tmp/xray
cp /tmp/xray/xray /opt/bin/
cp /tmp/xray/*.dat /opt/share/
# Preserve the bundled Xray categories. Auto uses a separate full country database.
curl --fail --location --retry 4 https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat -o /opt/share/country-geoip.dat
echo 'eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2  /opt/share/country-geoip.dat' | sha256sum -c -
file="tailscale_${TAILSCALE_VERSION}_${tarch}.tgz"
curl --fail --location --retry 4 "https://pkgs.tailscale.com/stable/$file" -o /tmp/ts.tgz
curl --fail --location --retry 4 "https://pkgs.tailscale.com/stable/$file.sha256" -o /tmp/ts.sha
printf '%s  /tmp/ts.tgz\n' "$(cut -d ' ' -f1 /tmp/ts.sha)" | sha256sum -c -
tar -xzf /tmp/ts.tgz -C /tmp/ts --strip-components=1
cp /tmp/ts/tailscale /tmp/ts/tailscaled /opt/bin/
chmod 755 /opt/bin/*
