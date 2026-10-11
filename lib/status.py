"""Read-only status: configuration, bounded systemd queries and cached probes."""
import argparse
import json
from pathlib import Path
import subprocess
import time

LABELS = {'adguard': 'AdGuard', 'vless': 'SKIPP'}
SETTINGS = '/etc/tg-vpn-failover/config.json'


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def configured_route(config):
    try:
        outbound = next(x for x in config['outbounds'] if x.get('tag') == 'active-upstream')
        return {1080: 'adguard', 1081: 'vless'}.get(outbound['server_port'])
    except (KeyError, TypeError, AttributeError, StopIteration):
        return None


def fresh(stamp, now):
    return type(stamp) in (int, float) and 0 <= now - stamp <= 90


def path_health(health, name, now):
    paths = health.get('paths')
    sample = paths.get(name, {}) if isinstance(paths, dict) else {}
    if not isinstance(sample, dict) or not fresh(sample.get('checked_at'), now):
        return None
    checks = sample.get('checks')
    if not isinstance(checks, dict) or not checks or any(type(v) is not bool for v in checks.values()):
        return None
    return all(checks.values())


def render(health, route, units, listening, now, verbose=False, mtproto=False, region='en'):
    current = (fresh(health.get('checked_at'), now) and health.get('active') == route and route in LABELS
               and health.get('region', 'en') == region)
    shared = path_health(health, 'shared', now) if current else None
    upstream = path_health(health, route, now) if current else None
    processes = units.get('shared') == 'active' and units.get(route) == 'active'
    label = LABELS.get(route, 'не определён')
    # The en (Telegram) line stays as before so existing bot screens do not change.
    vpn_name = 'VPN' if region == 'en' else 'VPN ' + region.upper()
    if not processes:
        vpn = f'❌ {vpn_name}: {label}'
    elif shared is None or upstream is None:
        vpn = f'⚠️ {vpn_name}: {label}'
    elif shared and upstream:
        vpn = f'✅ {vpn_name}: {label}'
    else:
        vpn = f'❌ {vpn_name}: {label}'
    local_mtg = units.get('mtg') == 'active' and listening
    mtg = '✅ MTProto' if local_mtg else '❌ MTProto'
    if mtproto:
        return mtg
    lines = [vpn]
    if verbose:
        for name in ('adguard', 'vless', 'shared'):
            value = path_health(health, name, now) if current else None
            icon = '⚠️' if value is None else '✅' if value else '❌'
            detail = 'нет свежих данных' if value is None else 'проверки пройдены' if value else 'есть ошибка проверки'
            lines.append(f"{icon} {LABELS.get(name, 'Общий SOCKS')}: {detail}")
        lines.append(mtg)
        if units.get('timer') != 'active':
            lines.append('❌ Failover: таймер не работает')
        elif units.get('result') != 'success':
            lines.append('⚠️ Failover: последнее выполнение завершилось ошибкой')
        elif not current:
            lines.append('⚠️ Failover: таймер включён, актуальной проверки нет')
        else:
            lines.append(f"✅ Failover: проверка {int(now-health['checked_at'])} с назад")
    return '\n'.join(lines)


def command(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ''


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--verbose', action='store_true')
    modes.add_argument('--mtproto', action='store_true')
    args = parser.parse_args()
    health = read_json('/run/mtproxy-failover/health.json')
    route = configured_route(read_json('/etc/sing-box/mtproxy-egress.json'))
    settings = read_json(SETTINGS)
    region = settings.get('region', 'en')
    units = {name: command(['/usr/bin/systemctl', 'is-active', unit]) for name, unit in {
        'shared': 'mtproxy-egress.service', 'adguard': settings.get('adguard_unit') or 'egg-cam-adguard.service',
        'vless': 'mtproxy-vless.service', 'mtg': 'mtg.service', 'timer': 'mtproxy-failover.timer',
    }.items()}
    units['result'] = command(['/usr/bin/systemctl', 'show', 'mtproxy-failover.service', '-p', 'Result', '--value'])
    ports = command(['/usr/bin/ss', '-H', '-lnt'])
    listening = any(len(row.split()) > 3 and row.split()[3].rsplit(':', 1)[-1] == '443' for row in ports.splitlines())
    print(render(health, route, units, listening, time.time(), args.verbose, args.mtproto, region))


if __name__ == '__main__':
    main()
