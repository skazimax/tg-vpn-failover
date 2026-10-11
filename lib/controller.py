#!/usr/bin/env python3
"""Root-owned VPN egress controller with a ru/en region switch; CLI paths are intentionally fixed."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import copy
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import syslog
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit
import uuid

PORTS = {"adguard": 1080, "vless": 1081, "shared": 1079}
UNITS = {"adguard": "egg-cam-adguard.service", "vless": "mtproxy-vless.service", "shared": "mtproxy-egress.service"}
CORE_URL = "https://core.telegram.org/getProxyConfig"
API_URL = "https://api.telegram.org/bot0:invalid/getMe"
SETTINGS = Path("/etc/tg-vpn-failover/config.json")
ADGUARD_ENV = Path("/etc/tg-vpn-failover/adguard.env")


def telegram_core(status, body):
    return status == 200 and any(line.startswith(b"proxy_for ") for line in body.splitlines())


def telegram_api(status, body):
    try:
        reply = json.loads(body)
        return status == 401 and reply.get("ok") is False and reply.get("error_code") == 401
    except (ValueError, AttributeError):
        return False


def reachable(status, body):
    # Russian services drop foreign addresses silently; any HTTP answer proves a Russian exit.
    return status > 0


# Each region: health probes, VLESS groups in priority order (include all / exclude any
# name fragments; gRPC preferred inside a group) and the AdGuard location to use.
REGIONS = {
    "en": {
        "label": "EN",
        "probes": (("core", CORE_URL, telegram_core), ("api", API_URL, telegram_api)),
        "groups": ((("авто",), ("авто+",)), (("авто+",), ())),
        "adguard_location": "Frankfurt",
    },
    "ru": {
        "label": "RU",
        "probes": (("mos", "https://school.mos.ru/", reachable),
                   ("dnevnik", "https://dnevnik.mos.ru/", reachable)),
        "groups": ((("россия",), ("белые списки",)), (("россия",), ())),
        "adguard_location": "Moscow",
    },
}


class OperationError(RuntimeError):
    pass


class Busy(OperationError):
    pass


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def build_backup(raw: bytes, region="en") -> dict:
    data = b"".join(raw.split())
    if len(data) > 2 * 1024 * 1024:
        raise OperationError("subscription too large")
    decoded = base64.b64decode(data + b"=" * (-len(data) % 4), validate=True).decode()
    records = [line.strip() for line in decoded.splitlines() if line.strip().startswith("vless://")]
    name = lambda item: unquote(urlsplit(item).fragment).casefold()
    selected = []
    for include, exclude in REGIONS[region]["groups"]:
        group = [item for item in records
                 if all(part in name(item) for part in include) and not any(part in name(item) for part in exclude)]
        grpc = [item for item in group if parse_qs(urlsplit(item).query).get("type") == ["grpc"]]
        selected = grpc or group
        if selected:
            break
    if not selected:
        raise OperationError("no VLESS group for region " + region)
    nodes = {}
    for record in selected:
        uri = urlsplit(record)
        query = {key: values[0] for key, values in parse_qs(uri.query).items()}
        if not uri.hostname or not uri.port or not uri.username:
            raise OperationError("incomplete VLESS endpoint")
        if any(not query.get(key) for key in ("security", "sni", "fp", "pbk", "sid", "type")):
            raise OperationError("incomplete VLESS parameters")
        if query["security"] != "reality":
            raise OperationError("unsupported VLESS security")
        node = {
            "type": "vless", "server": uri.hostname, "server_port": uri.port,
            "uuid": str(uuid.UUID(unquote(uri.username))),
            "tls": {"enabled": True, "server_name": query["sni"],
                    "utls": {"enabled": True, "fingerprint": query["fp"]},
                    "reality": {"enabled": True, "public_key": query["pbk"], "short_id": query["sid"]}},
        }
        if query.get("flow"):
            node["flow"] = query["flow"]
        if query["type"] == "grpc":
            node["transport"] = {"type": "grpc", "service_name": query.get("serviceName", "")}
        elif query["type"] not in ("tcp", "raw"):
            raise OperationError("unsupported VLESS transport")
        # Names/order in the provider response do not cause needless restarts.
        fingerprint = hashlib.sha256(encoded(node)).hexdigest()
        node["tag"] = "vless-" + fingerprint[:16]
        nodes[fingerprint] = node
    outbounds = [nodes[key] for key in sorted(nodes)]
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1081}],
        "outbounds": [{"type": "urltest", "tag": "vless-auto", "outbounds": [n["tag"] for n in outbounds],
                       "url": REGIONS[region]["probes"][0][1], "interval": "1m", "tolerance": 150, "idle_timeout": "10m",
                       "interrupt_exist_connections": False}, *outbounds],
    }


class Controller:
    def __init__(self, config_dir=Path("/etc/sing-box"), runtime=Path("/run/mtproxy-failover"), gid=None,
                 settings=SETTINGS, adguard_env=ADGUARD_ENV):
        self.settings = Path(settings)
        self.adguard_env = Path(adguard_env)
        values = self.read_json(self.settings, {})
        values = values if isinstance(values, dict) else {}
        self.region = values.get("region", "en")
        if self.region not in REGIONS:
            raise OperationError("unknown region in settings")
        self.units = dict(UNITS, adguard=values.get("adguard_unit") or UNITS["adguard"])
        self.config_dir = Path(config_dir)
        self.runtime = Path(runtime)
        self.gid = grp.getgrnam("mtproxy-vless").gr_gid if gid is None else gid
        self.egress = self.config_dir / "mtproxy-egress.json"
        self.backup = self.config_dir / "mtproxy-backup.json"
        self.journal = self.config_dir / ".mtproxy-transaction.json"
        self.runtime.mkdir(mode=0o755, parents=True, exist_ok=True)
        self.runtime.chmod(0o755)

    def log(self, message):
        syslog.openlog("mtproxy-failover")
        syslog.syslog(syslog.LOG_NOTICE, message)

    def command(self, args, timeout=25, data=None):
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        if result.returncode:
            # Never include command arguments, output, or URLs containing secrets.
            raise OperationError("external command failed: " + Path(args[0]).name)
        return result.stdout

    @contextlib.contextmanager
    def lock(self, wait=30, name="lock"):
        with (self.runtime / name).open("a") as handle:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Busy("controller busy")
                    time.sleep(0.1)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def sync_dir(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def atomic_write(self, path, data, mode=0o644, gid=None):
        fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), mode)
                os.fchown(output.fileno(), os.geteuid(), os.getegid() if gid is None else gid)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(tmp, path)
            self.sync_dir(path.parent)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def read_json(self, path, default=None):
        try:
            return json.loads(path.read_bytes())
        except (OSError, ValueError):
            return default

    def current_route(self):
        config = json.loads(self.egress.read_bytes())
        upstream = next(n for n in config["outbounds"] if n.get("tag") == "active-upstream")
        if upstream.get("server") != "127.0.0.1":
            raise OperationError("unexpected egress server")
        return next(name for name in ("adguard", "vless") if PORTS[name] == upstream["server_port"])

    def set_state(self, route, failures=0):
        self.atomic_write(self.runtime / "state", (route + "\n").encode())
        self.atomic_write(self.runtime / "failures", (str(failures) + "\n").encode())

    def failures(self):
        try:
            return max(0, min(1000000, int((self.runtime / "failures").read_text())))
        except (OSError, ValueError):
            return 0

    def http(self, port, url):
        config = "url = " + json.dumps(url) + "\nproxy = " + json.dumps(f"socks5h://127.0.0.1:{port}") + "\n"
        try:
            output = self.command([
                "/usr/bin/curl", "-4", "-sS", "--connect-timeout", "3", "--max-time", "5",
                "--max-filesize", "262144", "--noproxy", "", "--config", "-", "-w", "\n%{http_code}",
            ], timeout=7, data=config.encode())
            body, _, status = output.rpartition(b"\n")
            return int(status), body
        except (OperationError, subprocess.TimeoutExpired, ValueError):
            return 0, b""

    def probe(self, port):
        checks = {name: check(*self.http(port, url)) for name, url, check in REGIONS[self.region]["probes"]}
        return {"checks": checks, "ok": all(checks.values())}

    def wait_healthy(self, port, attempts=2):
        for attempt in range(attempts):
            if self.probe(port)["ok"]:
                return True
            if attempt + 1 < attempts:
                time.sleep(1)
        return False

    def observe(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            values = list(pool.map(self.probe, PORTS.values()))
        return dict(zip(PORTS, values))

    def record_health(self, samples):
        previous = self.read_json(self.runtime / "health.json", {})
        now = int(time.time())
        for name, sample in samples.items():
            sample["checked_at"] = now
            sample["last_ok"] = now if sample["ok"] else previous.get("paths", {}).get(name, {}).get("last_ok")
            old = previous.get("paths", {}).get(name, {}).get("ok")
            if old != sample["ok"] and (old is not None or not sample["ok"]):
                self.log(name + " " + self.region + (" route recovered" if sample["ok"] else " route unavailable"))
        self.atomic_write(self.runtime / "health.json", encoded({
            "checked_at": now, "region": self.region, "active": self.current_route(),
            "failures": self.failures(), "paths": samples,
        }))

    def active(self, route):
        return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", self.units[route]], capture_output=True).returncode == 0

    def restart(self, route):
        self.command(["/usr/bin/systemctl", "restart", self.units[route]], timeout=25)
        # Type=simple becomes active before SOCKS binds. Avoid interpreting
        # that short startup window as another failure immediately after rollback.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", PORTS[route]), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)

    def stop(self, route):
        self.command(["/usr/bin/systemctl", "stop", self.units[route]])

    def ensure_upstream(self, route):
        if self.probe(PORTS[route])["ok"]:
            return
        self.restart(route)
        if not self.wait_healthy(PORTS[route]):
            raise OperationError("target upstream unavailable")

    def validate_config(self, candidate):
        with tempfile.TemporaryDirectory(prefix="check-", dir=self.runtime) as temp:
            path = Path(temp) / "config.json"
            path.write_bytes(encoded(candidate))
            self.command(["/usr/bin/sing-box", "check", "-c", str(path)], timeout=10)

    def recover_transaction(self):
        if not self.journal.exists():
            return
        txn = json.loads(self.journal.read_bytes())
        kind = txn["kind"]
        if kind not in ("shared", "vless"):
            raise OperationError("invalid recovery journal")
        path = self.egress if kind == "shared" else self.backup
        old = txn["before"]
        if old is None:
            path.unlink(missing_ok=True)
            self.sync_dir(path.parent)
        else:
            self.atomic_write(path, base64.b64decode(old), 0o640, self.gid)
        if txn["was_active"] and old is not None:
            self.restart(kind)
        else:
            self.stop(kind)
        if self.egress.exists():
            self.set_state(self.current_route(), self.failures())
        self.journal.unlink()
        self.sync_dir(self.journal.parent)
        self.log("rolled back interrupted or failed " + kind + " configuration change")

    def apply_config(self, kind, candidate):
        """Caller holds the shared lock; journal survives process/host crashes."""
        path = self.egress if kind == "shared" else self.backup
        self.validate_config(candidate)
        old = path.read_bytes() if path.exists() else None
        if old is not None and json.loads(old) == candidate:
            return False
        if self.journal.exists():
            raise OperationError("unrecovered configuration transaction")
        was_active = self.active(kind)
        txn = {"kind": kind, "before": None if old is None else base64.b64encode(old).decode(), "was_active": was_active}
        self.atomic_write(self.journal, encoded(txn), 0o600)
        try:
            self.atomic_write(path, encoded(candidate), 0o640, self.gid)
            self.restart(kind)
            if not self.wait_healthy(PORTS[kind]):
                raise OperationError("applied configuration failed " + self.region + " checks")
            if kind == "vless" and self.egress.exists() and self.current_route() == "vless":
                if not self.wait_healthy(PORTS["shared"]):
                    raise OperationError("shared route failed after VLESS update")
            if kind == "vless" and not was_active:
                self.stop(kind)
            self.journal.unlink()
            self.sync_dir(self.journal.parent)
        except BaseException:
            self.recover_transaction()
            raise
        return True

    def switch_to(self, target):
        old_route = self.current_route()
        if target == old_route:
            return
        self.ensure_upstream(target)
        candidate = json.loads(self.egress.read_bytes())
        next(n for n in candidate["outbounds"] if n.get("tag") == "active-upstream")["server_port"] = PORTS[target]
        self.apply_config("shared", candidate)
        self.set_state(target)
        self.log("switched shared " + self.region + " egress from " + old_route + " to " + target)

    def tick(self):
        self.recover_transaction()
        route = self.current_route()  # Persistent config overrides stale /run state.
        self.set_state(route, self.failures())
        samples = self.observe()
        self.record_health(samples)
        if samples[route]["ok"]:
            if not samples["shared"]["ok"]:
                self.log("upstream healthy; repairing shared SOCKS without switching VPN")
                self.restart("shared")
                if not self.wait_healthy(PORTS["shared"]):
                    self.set_state(route, self.failures() + 1)
                    self.record_health(self.observe())
                    raise OperationError("shared SOCKS repair failed")
            self.set_state(route)
            self.record_health(samples if samples["shared"]["ok"] else self.observe())
            return
        failures = self.failures() + 1
        self.set_state(route, failures)
        self.record_health(samples)
        self.log(self.region + " probe failed on " + route + " (" + str(failures) + "/3)")
        if failures >= 3:
            self.switch_to("vless" if route == "adguard" else "adguard")
            self.record_health(self.observe())

    def download(self):
        lines = Path("/etc/mtproxy-failover/subscriptions").read_text().splitlines()
        url = next(line.strip() for line in lines if line.strip())
        if urlsplit(url).scheme != "https":
            raise OperationError("subscription must use HTTPS")
        # Feed the secret subscription URL through stdin, never process argv.
        return self.command([
            "/usr/bin/curl", "-4", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
            "--connect-timeout", "10", "--max-time", "45", "--max-filesize", "2097152",
            "-A", "v2rayN/7.0", "--config", "-",
        ], timeout=50, data=("url = " + json.dumps(url) + "\n").encode())

    def restart_adguard(self):
        self.restart("adguard")
        if not self.wait_healthy(PORTS["adguard"]):
            if self.current_route() == "adguard":
                self.switch_to("vless")
            else:
                raise OperationError("standby AdGuard did not recover")
        self.tick()

    def candidate_check(self, candidate):
        self.validate_config(candidate)
        with tempfile.TemporaryDirectory(prefix="candidate-", dir=self.runtime) as temp:
            directory = Path(temp)
            os.chown(directory, 0, self.gid)
            directory.chmod(0o750)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            config = copy.deepcopy(candidate)
            config["inbounds"][0]["listen_port"] = port
            path = directory / "config.json"
            self.atomic_write(path, encoded(config), 0o640, self.gid)
            user = pwd.getpwnam("mtproxy-vless")
            with (directory / "sing-box.log").open("wb") as log:
                process = subprocess.Popen([
                    "/usr/bin/sing-box", "run", "-c", str(path),
                ], stdout=log, stderr=log, user=user.pw_uid, group=self.gid, extra_groups=[])
                try:
                    time.sleep(1)
                    if process.poll() is not None or not self.wait_healthy(port):
                        raise OperationError("candidate VLESS route unavailable")
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

    def update(self):
        # Serialize downloaders; failover stays available during download/probe.
        with self.lock(wait=1, name="update.lock"):
            candidate = build_backup(self.download(), self.region)
            with self.lock():
                self.recover_transaction()
                if self.read_json(self.backup) == candidate:
                    self.log("VLESS subscription unchanged; no restart")
                    return
            self.candidate_check(candidate)
            with self.lock():
                self.recover_transaction()
                self.apply_config("vless", candidate)
                self.log("VLESS subscription applied after isolated and live " + self.region + " checks")

    def write_region(self):
        self.settings.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        values = self.read_json(self.settings, {})
        values = values if isinstance(values, dict) else {}
        values["region"] = self.region
        self.atomic_write(self.settings, encoded(values), 0o644)
        location = REGIONS[self.region]["adguard_location"]
        self.atomic_write(self.adguard_env, ("ADGUARD_LOCATION=" + location + "\n").encode(), 0o644)

    def set_region(self, region):
        """Rebuild VLESS for the region, persist the switch, then move AdGuard and the shared route."""
        if region not in REGIONS:
            raise OperationError("unknown region")
        old = self.region
        self.region = region
        persisted = False
        try:
            with self.lock(wait=1, name="update.lock"):
                candidate = build_backup(self.download(), region)
                self.candidate_check(candidate)
                with self.lock(wait=30):
                    self.recover_transaction()
                    self.apply_config("vless", candidate)
                    self.write_region()
                    persisted = True
                    self.log("region switched from " + old + " to " + region)
                    self.restart("adguard")
                    route = self.current_route()
                    samples = self.observe()
                    if not samples[route]["ok"]:
                        other = "vless" if route == "adguard" else "adguard"
                        if samples[other]["ok"]:
                            self.switch_to(other)
                    self.set_state(self.current_route())
                    self.record_health(self.observe())
        except BaseException:
            if not persisted:
                self.region = old
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--force-switch", action="store_true")
    modes.add_argument("--restart-adguard", action="store_true")
    modes.add_argument("--update", action="store_true")
    modes.add_argument("--region", choices=sorted(REGIONS))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required")
    os.umask(0o077)
    controller = Controller()
    try:
        if args.region:
            controller.set_region(args.region)
        elif args.update:
            controller.update()
        else:
            with controller.lock(wait=30 if args.force_switch or args.restart_adguard else 0):
                controller.recover_transaction()
                if args.force_switch:
                    controller.switch_to("vless" if controller.current_route() == "adguard" else "adguard")
                    controller.record_health(controller.observe())
                elif args.restart_adguard:
                    controller.restart_adguard()
                else:
                    controller.tick()
    except Busy:
        if not (args.force_switch or args.restart_adguard or args.update or args.region):
            return 0
        print("VPN controller is busy; retry later", file=sys.stderr)
        return 1
    except Exception as exc:
        # urllib/curl/JSON exceptions can contain subscription credentials.
        reason = str(exc) if isinstance(exc, OperationError) else type(exc).__name__
        controller.log("VPN operation failed: " + reason)
        print("VPN operation failed: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
