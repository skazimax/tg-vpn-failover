import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, quote

spec = importlib.util.spec_from_file_location("controller", Path(__file__).parents[1] / "lib/controller.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def record(name="Авто · 1", transport="grpc", host="one.example"):
    query = {"security": "reality", "sni": "example.com", "fp": "chrome", "pbk": "A" * 43,
             "sid": "abcd", "type": transport}
    if transport == "grpc":
        query["serviceName"] = "service"
    else:
        query["flow"] = "xtls-rprx-vision"
    return "vless://00000000-0000-0000-0000-000000000001@" + host + ":443?" + urlencode(query) + "#" + quote(name)


def subscription(*records):
    return base64.b64encode("\n".join(records).encode())


def egress(route="adguard"):
    return {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 1079}],
            "outbounds": [{"type": "socks", "tag": "active-upstream", "server": "127.0.0.1", "server_port": m.PORTS[route]}]}


class FakeController(m.Controller):
    def __init__(self, root):
        (root / "config").mkdir()
        super().__init__(root / "config", root / "run", os.getgid(),
                         settings=root / "settings.json", adguard_env=root / "adguard.env")
        self.egress.write_bytes(m.encoded(egress()))
        self.backup.write_bytes(m.encoded(m.build_backup(subscription(record()))))
        self.good = {port: True for port in m.PORTS.values()}
        self.running = {name: True for name in m.PORTS}
        self.restarts = []
        self.stops = []
        self.logs = []
        self.reject_config = False
        self.restart_hook = None
        self.raw = subscription(record())
        self.candidate_calls = 0

    def log(self, message):
        self.logs.append(message)

    def active(self, route):
        return self.running[route]

    def restart(self, route):
        self.restarts.append(route)
        self.running[route] = True
        if self.restart_hook:
            self.restart_hook(route)

    def stop(self, route):
        self.stops.append(route)
        self.running[route] = False

    def probe(self, port):
        ok = self.good[port]
        return {"checks": {"core": ok, "api": ok}, "ok": ok}

    def wait_healthy(self, port, attempts=2):
        return self.probe(port)["ok"]

    def validate_config(self, candidate):
        if self.reject_config:
            raise m.OperationError("invalid config")

    def download(self):
        return self.raw

    def candidate_check(self, candidate):
        # Downloader/preflight must not monopolize the failover lock.
        with self.lock(wait=0):
            self.candidate_calls += 1


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.c = FakeController(Path(self.temp.name))

    def test_healthy_tick_does_not_restart_and_repairs_stale_state(self):
        self.c.set_state("vless", 2)
        self.c.tick()
        self.assertEqual(self.c.restarts, [])
        self.assertEqual((self.c.runtime / "state").read_text(), "adguard\n")
        self.assertEqual(self.c.failures(), 0)
        health = self.c.read_json(self.c.runtime / "health.json")
        self.assertTrue(all(p["ok"] for p in health["paths"].values()))

    def test_shared_failure_repairs_shared_only(self):
        self.c.good[1079] = False
        self.c.restart_hook = lambda _: self.c.good.update({1079: True})
        self.c.tick()
        self.assertEqual(self.c.restarts, ["shared"])
        self.assertEqual(self.c.current_route(), "adguard")

    def test_failed_shared_repair_does_not_switch_healthy_upstream(self):
        self.c.good[1079] = False
        with self.assertRaises(m.OperationError):
            self.c.tick()
        self.assertEqual(self.c.current_route(), "adguard")
        self.assertFalse(self.c.read_json(self.c.runtime / "health.json")["paths"]["shared"]["ok"])

    def test_third_upstream_failure_switches_without_restarting_healthy_reserve(self):
        self.c.good[1080] = self.c.good[1079] = False
        self.c.restart_hook = lambda kind: self.c.good.update({1079: True})
        self.c.tick()
        self.c.tick()
        self.assertEqual(self.c.current_route(), "adguard")
        self.c.tick()
        self.assertEqual(self.c.current_route(), "vless")
        self.assertEqual(self.c.restarts, ["shared"])
        self.assertEqual(self.c.failures(), 0)

    def test_failed_target_does_not_modify_shared_configuration(self):
        old = self.c.egress.read_bytes()
        self.c.good[1081] = False
        with self.assertRaises(m.OperationError):
            self.c.switch_to("vless")
        self.assertEqual(self.c.egress.read_bytes(), old)
        self.assertEqual(self.c.restarts, ["vless"])

    def test_failed_post_switch_probe_restores_config_and_state(self):
        old = self.c.egress.read_bytes()
        self.c.good[1079] = False
        with self.assertRaises(m.OperationError):
            self.c.switch_to("vless")
        self.assertEqual(self.c.egress.read_bytes(), old)
        self.assertEqual((self.c.runtime / "state").read_text(), "adguard\n")
        self.assertFalse(self.c.journal.exists())
        self.assertEqual(self.c.restarts, ["shared", "shared"])

    def test_validation_failure_changes_nothing(self):
        old = self.c.egress.read_bytes()
        self.c.reject_config = True
        with self.assertRaises(m.OperationError):
            self.c.switch_to("vless")
        self.assertEqual(self.c.egress.read_bytes(), old)
        self.assertEqual(self.c.restarts, [])

    def test_crash_journal_is_recovered_on_next_tick(self):
        old = self.c.egress.read_bytes()
        self.c.journal.write_bytes(m.encoded({"kind": "shared", "before": base64.b64encode(old).decode(), "was_active": True}))
        self.c.egress.write_bytes(m.encoded(egress("vless")))
        self.c.tick()
        self.assertEqual(self.c.current_route(), "adguard")
        self.assertFalse(self.c.journal.exists())
        self.assertEqual(self.c.restarts, ["shared"])

    def test_failed_recovery_retains_journal_for_retry(self):
        old = self.c.egress.read_bytes()
        self.c.journal.write_bytes(m.encoded({"kind": "shared", "before": base64.b64encode(old).decode(), "was_active": True}))
        def fail(_):
            raise m.OperationError("restart failed")
        self.c.restart_hook = fail
        with self.assertRaises(m.OperationError):
            self.c.recover_transaction()
        self.assertTrue(self.c.journal.exists())

    def test_unchanged_subscription_does_not_restart(self):
        self.c.update()
        self.assertEqual(self.c.restarts, [])
        self.assertEqual(self.c.candidate_calls, 0)

    def test_candidate_failure_preserves_production(self):
        old = self.c.backup.read_bytes()
        self.c.raw = subscription(record(host="two.example"))
        with patch.object(self.c, "candidate_check", side_effect=m.OperationError("bad route")):
            with self.assertRaises(m.OperationError):
                self.c.update()
        self.assertEqual(self.c.backup.read_bytes(), old)
        self.assertEqual(self.c.restarts, [])

    def test_update_preflight_is_outside_shared_lock(self):
        self.c.raw = subscription(record(host="two.example"))
        self.c.update()
        self.assertEqual(self.c.candidate_calls, 1)
        self.assertEqual(self.c.restarts, ["vless"])

    def test_bad_live_update_rolls_back_previous_config(self):
        old = self.c.backup.read_bytes()
        self.c.raw = subscription(record(host="two.example"))
        self.c.good[1081] = False
        with self.assertRaises(m.OperationError):
            self.c.update()
        self.assertEqual(self.c.backup.read_bytes(), old)
        self.assertEqual(self.c.restarts, ["vless", "vless"])

    def test_active_vless_update_checks_common_path_too(self):
        old = self.c.backup.read_bytes()
        self.c.egress.write_bytes(m.encoded(egress("vless")))
        self.c.raw = subscription(record(host="two.example"))
        self.c.good[1079] = False
        with self.assertRaises(m.OperationError):
            self.c.update()
        self.assertEqual(self.c.backup.read_bytes(), old)

    def test_initial_failed_install_removes_new_config_and_stops_service(self):
        self.c.backup.unlink()
        self.c.running["vless"] = False
        self.c.good[1081] = False
        with self.assertRaises(m.OperationError):
            self.c.update()
        self.assertFalse(self.c.backup.exists())
        self.assertFalse(self.c.running["vless"])

    def test_shared_lock_excludes_second_writer(self):
        with self.c.lock(wait=0):
            with self.assertRaises(m.Busy):
                with self.c.lock(wait=0):
                    self.fail("second writer acquired lock")

    def test_atomic_write_failure_keeps_original_file(self):
        old = self.c.egress.read_bytes()
        with patch.object(m.os, "replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.c.atomic_write(self.c.egress, b"invalid", 0o640, os.getgid())
        self.assertEqual(self.c.egress.read_bytes(), old)

    def test_api_failure_marks_route_unhealthy_even_if_core_passes(self):
        with patch.object(self.c, "http", side_effect=[(200, b"proxy_for 1.1.1.1;"), (502, b"bad gateway")]):
            sample = m.Controller.probe(self.c, 1079)
        self.assertTrue(sample["checks"]["core"])
        self.assertFalse(sample["ok"])

    def test_expected_invalid_token_response_is_healthy(self):
        with patch.object(self.c, "http", side_effect=[(200, b"proxy_for 1.1.1.1;"), (401, b'{"ok":false,"error_code":401}')]):
            self.assertTrue(m.Controller.probe(self.c, 1079)["ok"])

    def test_ru_probe_accepts_any_http_answer(self):
        self.c.region = "ru"
        with patch.object(self.c, "http", side_effect=[(403, b""), (404, b"")]):
            self.assertTrue(m.Controller.probe(self.c, 1079)["ok"])
        with patch.object(self.c, "http", side_effect=[(200, b""), (0, b"")]):
            sample = m.Controller.probe(self.c, 1079)
        self.assertEqual(sample["checks"], {"mos": True, "dnevnik": False})
        self.assertFalse(sample["ok"])

    def test_region_switch_persists_settings_and_rebuilds_vless(self):
        self.c.raw = subscription(record("🇷🇺 Россия · 1", host="ru.example"))
        self.c.set_region("ru")
        self.assertEqual(self.c.region, "ru")
        self.assertEqual(self.c.read_json(self.c.settings)["region"], "ru")
        self.assertEqual(self.c.adguard_env.read_text(), "ADGUARD_LOCATION=Moscow\n")
        self.assertEqual(self.c.read_json(self.c.backup)["outbounds"][1]["server"], "ru.example")
        self.assertEqual(self.c.restarts, ["vless", "adguard"])
        self.assertEqual(self.c.read_json(self.c.runtime / "health.json")["region"], "ru")

    def test_region_switch_moves_shared_route_off_unhealthy_adguard(self):
        self.c.raw = subscription(record("🇷🇺 Россия · 1", host="ru.example"))
        self.c.good[1080] = False
        self.c.set_region("ru")
        self.assertEqual(self.c.current_route(), "vless")

    def test_failed_region_candidate_keeps_previous_region(self):
        old = self.c.backup.read_bytes()
        self.c.raw = subscription(record("🇷🇺 Россия · 1", host="ru.example"))
        with patch.object(self.c, "candidate_check", side_effect=m.OperationError("bad route")):
            with self.assertRaises(m.OperationError):
                self.c.set_region("ru")
        self.assertEqual(self.c.region, "en")
        self.assertFalse(self.c.settings.exists())
        self.assertEqual(self.c.backup.read_bytes(), old)

    def test_region_without_matching_nodes_is_rejected(self):
        with self.assertRaises(m.OperationError):
            self.c.set_region("ru")
        self.assertEqual(self.c.region, "en")
        with self.assertRaises(m.OperationError):
            self.c.set_region("de")

    def test_settings_select_region_and_adguard_unit(self):
        root = Path(self.temp.name) / "second"
        root.mkdir()
        (root / "settings.json").write_text('{"region": "ru", "adguard_unit": "adguardvpn.service"}')
        c = m.Controller(root / "config", root / "run", os.getgid(), settings=root / "settings.json")
        self.assertEqual(c.region, "ru")
        self.assertEqual(c.units["adguard"], "adguardvpn.service")

    def test_standby_restart_failure_is_reported(self):
        self.c.egress.write_bytes(m.encoded(egress("vless")))
        self.c.good[1080] = False
        with self.assertRaises(m.OperationError):
            self.c.restart_adguard()


class SubscriptionTest(unittest.TestCase):
    def test_regular_grpc_preferred(self):
        config = m.build_backup(subscription(record(), record("Авто+", "tcp", "plus.example"), record("Авто · 2", "tcp", "tcp.example")))
        self.assertEqual(len(config["outbounds"]), 2)
        self.assertEqual(config["outbounds"][1]["transport"]["type"], "grpc")
        self.assertFalse(config["outbounds"][0]["interrupt_exist_connections"])

    def test_group_fallbacks(self):
        for name in ["Авто", "Авто+"]:
            self.assertEqual(m.build_backup(subscription(record(name, "tcp")))["outbounds"][1]["flow"], "xtls-rprx-vision")

    def test_order_names_and_duplicates_do_not_change_config(self):
        first, second = record(host="one.example"), record(host="two.example")
        self.assertEqual(m.build_backup(subscription(first, second)), m.build_backup(subscription(second, first, first)))

    def test_ru_prefers_plain_russia_grpc(self):
        config = m.build_backup(subscription(
            record("🇷🇺 Россия · 1", "grpc", "ru-grpc.example"), record("🇷🇺 Россия · 2", "tcp", "ru-tcp.example"),
            record("🌩 Белые списки | 🇷🇺 Россия · 1", "grpc", "white.example"), record()), "ru")
        self.assertEqual([n["server"] for n in config["outbounds"][1:]], ["ru-grpc.example"])
        self.assertEqual(config["outbounds"][0]["url"], "https://school.mos.ru/")

    def test_ru_falls_back_to_whitelist_russia(self):
        config = m.build_backup(subscription(record("🌩 Белые списки | 🇷🇺 Россия · 1", "tcp", "white.example"), record()), "ru")
        self.assertEqual(config["outbounds"][1]["server"], "white.example")

    def test_en_ignores_russia_only_subscription(self):
        with self.assertRaises(m.OperationError):
            m.build_backup(subscription(record("🇷🇺 Россия · 1")))

    def test_invalid_subscriptions_rejected(self):
        for raw in [b"bad***", subscription(record("France")), subscription(record().replace("security=reality", "security=tls")), subscription(record().replace("type=grpc", "type=ws"))]:
            with self.assertRaises((ValueError, m.OperationError)):
                m.build_backup(raw)


if __name__ == "__main__":
    unittest.main()
