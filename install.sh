#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo_dir=$(cd "$(dirname "$0")" && pwd)
subscription_file=/etc/mtproxy-failover/subscriptions

command -v sing-box >/dev/null
command -v curl >/dev/null
command -v python3 >/dev/null
command -v flock >/dev/null
[[ -s "$subscription_file" ]] || {
  echo "$subscription_file is missing or empty" >&2
  exit 1
}

getent group mtproxy-vless >/dev/null || groupadd --system mtproxy-vless
id mtproxy-vless >/dev/null 2>&1 || useradd --system --gid mtproxy-vless \
  --home-dir /nonexistent --shell /usr/sbin/nologin mtproxy-vless

install -d -o root -g mtproxy-vless -m 0750 /etc/sing-box
install -d -o root -g root -m 0755 /etc/tg-vpn-failover
# Region (en: Telegram, ru: Russian exit) and AdGuard unit are chosen on first install;
# later switches go through `mtproxy-failover --region ru|en`.
if [[ ! -e /etc/tg-vpn-failover/config.json ]]; then
  region=${TG_VPN_REGION:-en}
  [[ $region == en || $region == ru ]] || { echo "TG_VPN_REGION must be en or ru" >&2; exit 1; }
  printf '{\n  "adguard_unit": "%s",\n  "region": "%s"\n}\n' \
    "${TG_VPN_ADGUARD_UNIT:-egg-cam-adguard.service}" "$region" > /etc/tg-vpn-failover/config.json
  location=Frankfurt; [[ $region == ru ]] && location=Moscow
  printf 'ADGUARD_LOCATION=%s\n' "$location" > /etc/tg-vpn-failover/adguard.env
  chmod 0644 /etc/tg-vpn-failover/config.json /etc/tg-vpn-failover/adguard.env
fi
install -d -o root -g root -m 0755 /usr/local/lib/tg-vpn-failover
install -o root -g root -m 0644 "$repo_dir/lib/status.py" /usr/local/lib/tg-vpn-failover/status.py
install -o root -g root -m 0644 "$repo_dir/lib/controller.py" \
  /usr/local/lib/tg-vpn-failover/controller.py
install -o root -g root -m 0755 "$repo_dir/scripts/mtproxy-vless-update" \
  /usr/local/sbin/mtproxy-vless-update
install -o root -g root -m 0755 "$repo_dir/scripts/mtproxy-failover" \
  /usr/local/sbin/mtproxy-failover
install -o root -g root -m 0755 "$repo_dir/scripts/tg-vpn-failover-status" \
  /usr/local/sbin/tg-vpn-failover-status
install -o root -g root -m 0644 "$repo_dir/systemd/"* \
  /etc/systemd/system/

if [[ ! -e /etc/sing-box/mtproxy-egress.json ]]; then
  install -o root -g mtproxy-vless -m 0640 \
    "$repo_dir/config/mtproxy-egress.json" /etc/sing-box/mtproxy-egress.json
fi

systemctl daemon-reload
/usr/local/sbin/mtproxy-vless-update
sing-box check -c /etc/sing-box/mtproxy-egress.json
# The current mtg + SOCKS egress architecture supersedes the legacy official
# MTProxy/redsocks updater. Leaving its timer enabled performs useless writes
# to an inactive service and makes the installed service set misleading.
systemctl disable --now mtproxy-update.timer mtproxy.service \
  mtproxy-routing.service redsocks.service >/dev/null 2>&1 || true
systemctl enable --now mtproxy-vless.service mtproxy-egress.service
systemctl enable --now mtproxy-failover.timer mtproxy-vless-update.timer
