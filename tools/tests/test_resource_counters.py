"""Контракт read-only счётчиков на ограниченных fixtures."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from resource_counters import Collector, Reading, interval, number


class CounterTests(unittest.TestCase):
    def test_numeric_bounds(self) -> None:
        for value in ("bad", "-1", "18446744073709551616", "1.5", ""):
            with self.assertRaises(ValueError):
                number(value)
        self.assertEqual(number("0"), 0)

    def test_energy_intervals(self) -> None:
        a = Reading("available", "ok", 10, 1, "package", 100, max_power_uw=50)
        b = Reading("available", "ok", 20, 1000000001, "package", 100, max_power_uw=50)
        self.assertEqual(interval(a, b).value, 10)
        for other, reason in (
            (
                Reading(
                    "available", "ok", 10, 1000000001, "package", 100, max_power_uw=50
                ),
                "quantization",
            ),
            (
                Reading(
                    "available", "ok", 1, 1000000001, "package", 100, max_power_uw=50
                ),
                "reset_or_wrap",
            ),
            (
                Reading("available", "ok", 20, 1, "package", 100, max_power_uw=50),
                "time",
            ),
            (Reading("unavailable", "charging"), "charging"),
        ):
            self.assertEqual(interval(a, other).reason, reason)

    def test_disabled_wakeups_and_missing_energy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "proc/sys/kernel/sched_schedstats"
            path.parent.mkdir(parents=True)
            path.write_text("0")
            collector = Collector._fixture(
                root / "proc", root / "power", root / "battery"
            )
            self.assertEqual(collector.wakeups(123).reason, "schedstats_disabled")
            self.assertEqual(collector.sample(123)["energy"]["status"], "unavailable")

    def test_sources_and_duplicate_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            power = root / "power"
            zone = power / "intel-rapl:0"
            zone.mkdir(parents=True)
            for name, value in {
                "name": "package-0",
                "energy_uj": "10",
                "max_energy_range_uj": "100",
            }.items():
                (zone / name).write_text(value)
            (power / "intel-rapl:1").symlink_to(zone, target_is_directory=True)
            supply = root / "battery/BAT0"
            supply.mkdir(parents=True)
            (supply / "type").write_text("Battery")
            (supply / "status").write_text("Charging")
            collector = Collector._fixture(root / "proc", power, root / "battery")
            readings = collector.energy()
            self.assertEqual(len([k for k in readings if k.startswith("intel")]), 1)
            self.assertEqual(readings["battery:BAT0"].reason, "not_discharging")
            (zone / "max_energy_range_uj").write_text("0")
            self.assertEqual(
                collector.energy()["intel-rapl:0"].reason, "malformed_or_limit"
            )

    def test_wakeups_identity_and_churn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            enabled = root / "proc/sys/kernel/sched_schedstats"
            enabled.parent.mkdir(parents=True)
            enabled.write_text("1")
            task = root / "proc/123/task/123"
            task.mkdir(parents=True)
            (task / "stat").write_text("123 (task) " + " ".join(["0"] * 19 + ["10"]))
            (task / "sched").write_text("se.statistics.nr_wakeups : 12")
            collector = Collector._fixture(
                root / "proc", root / "power", root / "battery"
            )
            before = collector.wakeups(123)
            self.assertEqual(before.value, 12)
            (task / "stat").write_text("123 (task) " + " ".join(["0"] * 19 + ["11"]))
            self.assertEqual(
                interval(before, collector.wakeups(123)).reason,
                "thread_churn_or_pid_reuse",
            )
            (task / "sched").write_text("se.statistics.nr_wakeups : -1")
            self.assertEqual(collector.wakeups(123).reason, "malformed_or_limit")

    def test_permissions_and_bounds(self) -> None:
        from resource_counters import failure, read

        self.assertEqual(failure(PermissionError()).reason, "permission_denied")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large"
            path.write_bytes(b"0" * 65537)
            with self.assertRaises(ValueError):
                read(path)
        a = Reading("available", "ok", 1, 1, "package", 100)
        b = Reading("available", "ok", 2, 1000000001, "package", 100)
        self.assertEqual(interval(a, b).reason, "wrap_bound_unknown")
        self.assertEqual(
            interval(a, Reading("available", "ok", 2, 1, "psys", 100)).reason,
            "source_changed",
        )


if __name__ == "__main__":
    unittest.main()
