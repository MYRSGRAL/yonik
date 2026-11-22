"""COMPONENT: настоящие Qt-действия и typed RPC на private bus, без production TUN/helper."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_smoke import Fixture
from desktop_ui_smoke import execute, ui

NAME = "cloud.highpriority.yonik.Network1"


def fixture(address: str, scenario: str, log: Path) -> None:
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBusGMainLoop(set_as_default=True)
    bus = dbus.bus.BusConnection(address)
    _name = dbus.service.BusName(NAME, bus)
    state = "no_managed_policy"
    revoke_first_session = scenario in ("reconnect-retained", "reconnect-state-unknown")
    revoke_unconfirmed = scenario == "reconnect-state-unknown"

    def record(method: str) -> None:
        with log.open("a") as stream:
            stream.write(json.dumps({"method": method, "at": time.monotonic()}) + "\n")

    class Service(dbus.service.Object):
        @dbus.service.method(NAME, in_signature="s", out_signature="s")
        def Capabilities(self, request: str) -> str:
            record("Capabilities")
            return json.dumps(
                dict(
                    version=1,
                    public_protection=True,
                    system_tun=scenario != "unsupported",
                    allow_lan=False,
                )
            )

        @dbus.service.method(
            NAME, in_signature="s", out_signature="s", async_callbacks=("ok", "error")
        )
        def Prepare(self, request: str, ok: object, error: object) -> None:
            record("Prepare")
            value = json.loads(request)
            assert set(value) == {"version", "mode", "engine", "kill_switch", "server", "policy"}
            assert value["mode"] == "system_profile_policy"
            assert value["policy"]["version"] == 1
            assert value["policy"]["default_action"] == ("block" if scenario == "policy" else "proxy")
            if scenario == "denied":
                error(
                    dbus.exceptions.DBusException(
                        json.dumps(dict(version=1, error="authorization")),
                        name=NAME + ".Error",
                    )
                )
            elif scenario in ("cancel", "stale", "policy-edit", "shutdown", "timeout"):
                GLib.timeout_add(
                    35000 if scenario == "timeout" else 2000,
                    lambda: (ok(json.dumps(dict(version=1, handle=[42] * 32))), False)[
                        1
                    ],
                )
            else:
                ok(json.dumps(dict(version=1, handle=[42] * 32)))

        @dbus.service.method(
            NAME, in_signature="sah", out_signature="s", async_callbacks=("ok", "error")
        )
        def ApplyOutputV1(
            self, request: str, output: list, ok: object, error: object
        ) -> None:
            nonlocal state
            record("Apply")
            assert json.loads(request)["handle"] == [42] * 32
            assert len(output) == 2
            for writer in output:
                os.close(writer.take())
            state = "tunnel_starting"
            if scenario == "owner":
                GLib.timeout_add(
                    100,
                    lambda: (
                        bus.release_name(NAME),
                        GLib.timeout_add(
                            250, lambda: (bus.request_name(NAME), False)[1]
                        ),
                        False,
                    )[2],
                )
            reply = json.dumps(dict(version=1, state=state))
            if scenario == "applycancel":
                GLib.timeout_add(2000, lambda: (ok(reply), False)[1])
            else:
                ok(reply)

        @dbus.service.method(
            NAME, in_signature="s", out_signature="s", async_callbacks=("ok", "error")
        )
        def State(self, request: str, ok: object, error: object) -> None:
            nonlocal state, revoke_first_session, revoke_unconfirmed
            record("State")
            if revoke_first_session and state == "tunnel_starting":
                if revoke_unconfirmed:
                    revoke_unconfirmed = False
                    ok(json.dumps(dict(version=1, state="unknown")))
                    return
                revoke_first_session = False
                state = "recovery_required"
            if scenario.startswith("retained-") and state == "verified_rules":
                if scenario == "retained-timeout-unlock":
                    GLib.timeout_add(
                        35000,
                        lambda: (
                            ok(json.dumps(dict(version=1, state="verified_rules"))),
                            False,
                        )[1],
                    )
                else:
                    if scenario == "retained-error-state":
                        state = "no_managed_policy"
                    if scenario == "retained-owner-unlock":

                        def restart() -> bool:
                            record("OwnerLost")
                            bus.release_name(NAME)

                            def returned() -> bool:
                                bus.request_name(NAME)
                                record("OwnerReturned")
                                return False

                            GLib.timeout_add(250, returned)
                            return False

                        GLib.timeout_add(100, restart)
                    error(
                        dbus.exceptions.DBusException(
                            json.dumps(dict(version=1, error="unavailable")),
                            name=NAME + ".Error",
                        )
                    )
                return
            if scenario == "stopunknown" and state == "unknown":
                ok(json.dumps(dict(version=1, state="no_managed_policy")))
                return
            ok(json.dumps(dict(version=1, state=state)))

        @dbus.service.method(NAME, in_signature="s", out_signature="s")
        def Stop(self, request: str) -> str:
            nonlocal state
            record("Stop")
            state = (
                "unknown"
                if scenario == "stopunknown"
                else (
                    "recovery_required"
                    if scenario in ("recovery", "reconnect-retained", "reconnect-state-unknown")
                    else "verified_rules"
                )
            )
            return json.dumps(dict(version=1, state=state))

        @dbus.service.method(NAME, in_signature="s", out_signature="s")
        def Unlock(self, request: str) -> str:
            nonlocal state
            record("Unlock")
            state = "no_managed_policy"
            return json.dumps(dict(version=1, state=state))

    _service = Service(bus, "/cloud/highpriority/yonik/Network")
    print("ready", flush=True)
    GLib.MainLoop().run()


def run(binary: Path, output: Path, scenario: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-system-qt-") as temporary:
        root = Path(temporary)
        daemon = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
            stdout=subprocess.PIPE,
            text=True,
        )
        address = daemon.stdout.readline().strip()
        service = subprocess.Popen(
            [
                sys.executable,
                __file__,
                "--fixture",
                address,
                scenario,
                str(output / "rpc.jsonl"),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        if service.stdout.readline().strip() != "ready":
            for process in (service, daemon):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
            raise RuntimeError("Не запущена собственная D-Bus fixture")
        handler = type(
            "SyntheticSubscription",
            (Fixture,),
            {"body": b"trojan://synthetic@192.0.2.1:443#SystemFixture"},
        )
        http = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=http.serve_forever)
        thread.start()
        old = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = address
        try:
            steps = [
                {
                    "when": {"ready": True},
                    "command": dict(
                        command="import_source",
                        name="Synthetic",
                        url=f"http://127.0.0.1:{http.server_port}/fixture",
                        local_exception=True,
                        route="direct",
                    ),
                },
                {
                    "when": {"profiles_count": 1, "busy": False},
                    "command": dict(command="select_profile", id=1, revision=1),
                },
                ui("click", "settingsButton", when={"selected_profile": 1}),
                ui("click", "settingsConnectionButton"),
                ui("key", "connectionModeChoice", key="Down"),
                ui("click", "homeButton", when={"connection_mode": "system"}),
                ui("click", "homeButton"),
                ui("click", "mainConnectButton", when={"can_connect": True}),
            ]
            if scenario == "policy":
                steps = steps[:5] + [
                    ui("click", "systemStateButton", when={"connection_mode": "system"}),
                    ui("click", "homeButton", when={"system_tun_available": True, "system_busy": False}),
                    ui("click", "settingsRoutingButton"),
                    {"command": {"command": "routing_default", "expected_revision": 0, "request_id": 91, "action": "block"}},
                    ui("click", "routingApplyButton", when={"routing_revision": 1}, expect={"routingApplyButton": {"enabled": True}}),
                ]
            if scenario in ("cancel", "applycancel", "stale", "policy-edit", "shutdown"):
                steps += [
                    ui(
                        "key",
                        "mainConnectButton",
                        key="Tab",
                        when={"status": "Preparing"},
                    )
                    for _ in range(8)
                ]
            if scenario in ("unsupported", "denied", "timeout"):
                error = {
                    "unsupported": "system_unsupported",
                    "denied": "system_denied",
                    "timeout": "system_timeout",
                }[scenario]
                steps += [
                    {
                        "when": {
                            "connection_error": error,
                            "can_stop": scenario == "timeout",
                        },
                        "command": {"command": "shutdown"},
                    }
                ]
            elif scenario == "policy":
                steps += [
                    {"when": {"status": "TunnelStarting"}, "command": {"command": "stop"}},
                    {"when": {"status": "VerifiedRules", "can_stop": False}, "command": {"command": "system_unlock"}},
                    {"when": {"system_state": "NoManagedPolicy", "system_busy": False}, "command": {"command": "shutdown"}},
                ]
            elif scenario in ("reconnect-retained", "reconnect-state-unknown"):
                if scenario == "reconnect-state-unknown":
                    steps.append(
                        ui(
                            "key",
                            "mainConnectButton",
                            key="Tab",
                            when={
                                "system_state": "Unknown",
                                "system_busy": False,
                                "can_stop": True,
                                "can_connect": False,
                            },
                        )
                    )
                steps += [
                    ui(
                        "click",
                        "mainConnectButton",
                        when={
                            "system_state": "RecoveryRequired",
                            "system_busy": False,
                            "can_connect": True,
                            "can_stop": False,
                            "can_unlock": True,
                        },
                    ),
                    ui(
                        "click",
                        "mainConnectButton",
                        when={"system_state": "TunnelStarting", "can_stop": True},
                    ),
                    {
                        "when": {
                            "system_state": "RecoveryRequired",
                            "system_busy": False,
                            "can_stop": False,
                            "can_unlock": True,
                        },
                        "command": {"command": "shutdown"},
                    },
                ]
            elif scenario == "shutdown":
                steps += [
                    {
                        "when": {"status": "Preparing"},
                        "command": {"command": "shutdown"},
                    }
                ]
            elif scenario.startswith("retained-"):
                steps += [
                    ui("click", "mainConnectButton", when={"status": "TunnelStarting"}),
                    ui(
                        "click",
                        "settingsButton",
                        when={"status": "VerifiedRules", "can_stop": False},
                    ),
                    ui("click", "settingsConnectionButton"),
                    ui("click", "systemStateButton", when={"system_busy": False}),
                ]
                error = (
                    "system_timeout"
                    if scenario == "retained-timeout-unlock"
                    else "system_unavailable"
                )
                if scenario == "retained-owner-unlock":
                    steps += [
                        ui(
                            "key",
                            "systemStateButton",
                            key="Tab",
                            when={"connection_error": error, "system_busy": False},
                        )
                        for _ in range(20)
                    ]
                steps += [
                    {
                        "when": {
                            "connection_error": error,
                            "system_busy": False,
                            "can_stop": False,
                        },
                        "command": {"command": "set_connection_mode", "mode": "local"},
                    }
                ]
                cleanup = (
                    "systemStateButton"
                    if scenario == "retained-error-state"
                    else "systemUnlockButton"
                )
                steps += [
                    ui(
                        "click",
                        cleanup,
                        when={
                            "connection_mode": "system",
                            "error": "busy",
                            "system_busy": False,
                        },
                        expect={
                            "connectionModeChoice": {"enabled": False},
                            "systemUnlockButton": {"enabled": True},
                        },
                    ),
                    {
                        "when": {
                            "system_state": "NoManagedPolicy",
                            "can_unlock": False,
                            "system_busy": False,
                        },
                        "command": {"command": "set_connection_mode", "mode": "local"},
                    },
                    {
                        "when": {"connection_mode": "local"},
                        "command": {"command": "shutdown"},
                    },
                ]
            elif scenario == "owner":
                steps += [
                    {
                        "when": {"status": "Unknown", "can_stop": True},
                        "command": {"command": "shutdown"},
                    }
                ]
            else:
                if scenario == "normal":
                    steps += [
                        {
                            "when": {"status": "TunnelStarting"},
                            "command": {
                                "command": "set_connection_mode",
                                "mode": "local",
                            },
                        }
                    ]
                when = {
                    "status": "Preparing"
                    if scenario in ("cancel", "applycancel", "stale", "policy-edit")
                    else "TunnelStarting"
                }
                if scenario == "policy-edit":
                    steps += [{"when": when, "command": {"command": "routing_default", "expected_revision": 0, "request_id": 99, "action": "block"}}]
                elif scenario == "stale":
                    steps += [
                        {
                            "when": when,
                            "command": dict(command="select_profile", id=1, revision=1),
                        }
                    ]
                else:
                    steps += [ui("click", "mainConnectButton", when=when)]
                if scenario == "normal":
                    steps += [
                        ui(
                            "click",
                            "mainConnectButton",
                            when={"status": "VerifiedRules", "can_stop": False},
                        ),
                        ui(
                            "click",
                            "mainConnectButton",
                            when={"status": "TunnelStarting"},
                        ),
                    ]
                if scenario in ("cancel", "applycancel", "stale"):
                    steps += [
                        ui(
                            "key",
                            "settingsButton",
                            key="Tab",
                            when={"status": "VerifiedRules"},
                        )
                        for _ in range(90)
                    ]
                if scenario == "stopunknown":
                    steps += [
                        ui(
                            "click",
                            "settingsButton",
                            when={
                                "status": "Unknown",
                                "can_stop": True,
                                "system_busy": False,
                            },
                        ),
                        ui("click", "settingsConnectionButton"),
                        ui("click", "systemStateButton", when={"system_busy": False}),
                        {
                            "when": {
                                "system_state": "NoManagedPolicy",
                                "can_stop": False,
                            },
                            "command": {"command": "shutdown"},
                        },
                    ]
                retained = (
                    "RecoveryRequired" if scenario == "recovery" else "VerifiedRules"
                )
                steps += (
                    []
                    if scenario == "stopunknown"
                    else [
                        ui(
                            "click",
                            "settingsButton",
                            when={"status": retained, "can_stop": False},
                        ),
                        ui("click", "settingsConnectionButton"),
                        ui("click", "systemStateButton", when={"system_busy": False}),
                        ui(
                            "click",
                            "systemUnlockButton",
                            when={"can_unlock": True, "system_busy": False},
                        ),
                        {
                            "when": {"system_state": "NoManagedPolicy"},
                            "command": {"command": "shutdown"},
                        },
                    ]
                )
            events = execute(binary, root, steps, output, "1")
            assert all(e.get("status") != "Connected" for e in events)
            if scenario in ("normal", "recovery", "cancel", "applycancel", "stale"):
                assert events[-1]["status"] == "NoManagedPolicy"
            calls = [
                json.loads(line)["method"]
                for line in (output / "rpc.jsonl").read_text().splitlines()
            ]
            if scenario in ("cancel", "applycancel", "stale", "policy-edit", "shutdown"):
                records = [
                    json.loads(line)
                    for line in (output / "rpc.jsonl").read_text().splitlines()
                ]
                started = next(
                    row["at"]
                    for row in records
                    if row["method"]
                    == ("Apply" if scenario == "applycancel" else "Prepare")
                )
                stopped = next(row["at"] for row in records if row["method"] == "Stop")
                assert stopped - started < 1.5, "Stop не ждёт долгий RPC"
            if scenario == "retained-owner-unlock":
                assert (
                    calls.index("OwnerLost")
                    < calls.index("OwnerReturned")
                    < calls.index("Unlock")
                )
            if scenario == "policy-edit":
                assert "Prepare" in calls and "Apply" not in calls
            if scenario == "normal":
                assert calls.count("Prepare") == 2 and calls.count("Apply") == 2
            if scenario in ("reconnect-retained", "reconnect-state-unknown"):
                assert [
                    method
                    for method in calls
                    if method in ("Prepare", "Apply", "Stop", "Unlock")
                ] == ["Prepare", "Apply", "Prepare", "Apply", "Stop"]
            if scenario == "unsupported":
                assert (
                    "Prepare" not in calls
                    and "Apply" not in calls
                    and "Stop" not in calls
                )
            if scenario in ("denied", "cancel", "stale", "policy-edit", "shutdown", "timeout"):
                assert "Apply" not in calls
            if scenario in ("normal", "recovery"):
                assert all(
                    method in calls for method in ("Prepare", "Apply", "Stop", "Unlock")
                )
        finally:
            if old is None:
                os.environ.pop("DBUS_SYSTEM_BUS_ADDRESS", None)
            else:
                os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = old
            http.shutdown()
            thread.join()
            http.server_close()
            for process in (service, daemon):
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1] == "--fixture":
        fixture(sys.argv[2], sys.argv[3], Path(sys.argv[4]))
    else:
        for scenario in sys.argv[3:] or [
            "normal",
            "unsupported",
            "denied",
            "cancel",
            "applycancel",
            "stale",
            "shutdown",
            "owner",
            "recovery",
            "reconnect-retained",
            "reconnect-state-unknown",
            "stopunknown",
            "timeout",
            "retained-error-unlock",
            "retained-timeout-unlock",
            "retained-owner-unlock",
            "retained-error-state",
        ]:
            run(
                Path(sys.argv[1]).resolve(),
                Path(sys.argv[2]).resolve() / scenario,
                scenario,
            )
