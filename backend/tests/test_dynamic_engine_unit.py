import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from app.engines import dynamic
from app.engines.dynamic import emulator_manager


class TestDynamicParsers(unittest.TestCase):
    def test_hex_to_ip_v4_and_v6(self):
        self.assertEqual(emulator_manager._hex_to_ip("0100007F"), "127.0.0.1")
        self.assertEqual(emulator_manager._hex_to_ip("0000000000000000FFFF00000100007F"), "127.0.0.1")
        self.assertEqual(emulator_manager._hex_to_ip("00000000000000000000000000000000"), "::")

    def test_snapshot_uid_sockets_filters_by_uid(self):
        tcp = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0F02000A:A1B2 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000 10209 0 1 1\n"
            "   1: 0F02000A:A1B3 5DB8D822:0050 01 00000000:00000000 00:00000000 00000000 10155 0 2 1\n"
        )

        def fake_adb(args, device=None, timeout=30):
            return {"success": True, "stdout": tcp if args[-1] == "/proc/net/tcp" else "", "stderr": ""}

        with patch.object(emulator_manager, "_run_adb", side_effect=fake_adb):
            socks = emulator_manager.snapshot_uid_sockets(10209, "emulator-5554")
        self.assertEqual(socks, [{"ip": "34.216.184.93", "port": 443, "protocol": "TCP", "state": "ESTABLISHED"}])

    def test_system_events_only_for_target_package(self):
        log = (
            "10-02 02:03:04.012 799 2733 I wm_create_activity: [0,7332,11,owasp.sat.agoat/.SplashActivity,MAIN,NULL,NULL,0]\n"
            "10-02 02:03:05.012 799 2733 I wm_create_activity: [0,7333,12,com.other/.Main,MAIN,NULL,NULL,0]\n"
        )
        events = dynamic._parse_system_events(log, "owasp.sat.agoat")
        self.assertEqual([(e["api_call"], e["description"]) for e in events],
                         [("Activity Launched", ".SplashActivity")])

    def test_tls_sni(self):
        sni = b"example.com"
        ext = b"\x00\x00" + (len(sni) + 5).to_bytes(2, "big") + (len(sni) + 3).to_bytes(2, "big") + b"\x00" + len(sni).to_bytes(2, "big") + sni
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(dynamic._tls_sni(record), "example.com")

    def test_build_network_attributes_hostnames(self):
        sockets = {"1.2.3.4:443:TCP": {"ip": "1.2.3.4", "port": 443, "protocol": "TCP"},
                   "10.0.2.3:53:UDP": {"ip": "10.0.2.3", "port": 53, "protocol": "UDP"}}
        pcap = {"dns": {"c2.example": ["1.2.3.4"], "dead.example": []}, "bytes": {"1.2.3.4": {"sent": 10, "recv": 20}}}
        net = dynamic._build_network(sockets, pcap, {"dead.example"})
        self.assertEqual(net[0]["destination"], "c2.example")
        self.assertEqual(net[0]["protocol"], "HTTPS")
        self.assertEqual(net[1]["destination"], "dead.example")
        self.assertEqual(len(net), 2)  # emulator gateway excluded


class TestDynamicFallback(unittest.TestCase):
    def test_falls_back_to_heuristic_when_no_emulator(self):
        case_dir = tempfile.mkdtemp()
        try:
            with patch.object(emulator_manager, "ensure_emulator", return_value=None), \
                 patch.object(dynamic.heuristic_analyzer, "run_heuristic_analysis",
                              return_value={"status": "completed", "events": [], "risk_score": 0}):
                result = dynamic.run_full_dynamic_analysis("x.apk", case_dir, duration=1)
            self.assertEqual(result["mode"], "heuristic")
            self.assertTrue(any("No Android emulator" in e for e in result["errors"]))
            self.assertTrue(os.path.exists(os.path.join(case_dir, "dynamic_analysis", "dynamic_report.json")))
        finally:
            shutil.rmtree(case_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
