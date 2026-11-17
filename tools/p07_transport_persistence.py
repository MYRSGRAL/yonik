"""Короткий production GUI persistence witness с private Secret Service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path


def gui_campaign(
    binary: Path,
    root: Path,
    output: Path,
    env: dict[str, str],
    inspect: Callable[[], dict],
) -> dict:
    """Production commands только для seed/backup; order/mode/save через UI."""
    from desktop_ui_smoke import ui

    selector = []
    mixed = dict(
        id=41,
        enabled=False,
        executables=["/usr/bin/browser", "/usr/bin/other"],
        domains=["example.org", "*.example.net"],
        destinations=["192.0.2.0/24", "2001:db8::/32"],
        action="block",
        platform_sources=selector,
        transport={
            "transport_protocols": ["tcp"],
            "destination_ports": [[443, 443], [8000, 8080]],
        },
    )
    other = dict(
        id=42,
        enabled=True,
        executables=[],
        domains=["other.example.org"],
        destinations=[],
        action="direct",
        platform_sources=[],
    )
    initial = dict(
        version=3, rules=[mixed, other], default_action="proxy", ru_direct=None
    )
    ordered = dict(initial, rules=[other, mixed])
    active_rule = dict(mixed, enabled=True)
    active = dict(initial, rules=[other, active_rule])
    fields = {
        "routingExecutable": {"text": "\n".join(mixed["executables"])},
        "routingDomain": {"text": "\n".join(mixed["domains"])},
        "routingCidr": {"text": "\n".join(mixed["destinations"])},
    }

    simple_fields = {
        name: dict(value, visible=name == "routingExecutable")
        for name, value in fields.items()
    }
    advanced_fields = {
        name: dict(value, visible=True) for name, value in fields.items()
    }

    def command(payload: dict, when: dict | None = None) -> dict:
        return {"when": when or {}, "command": payload}

    def button(target: str, **kwargs: object) -> dict:
        return ui("key", target, key="Space", **kwargs)

    owners = []

    def launch(stage: str, steps: list[dict]) -> list[dict]:
        script = output / (stage + "-script.json")
        trace = output / (stage + "-trace.jsonl")
        script.write_text(json.dumps({"steps": steps}, ensure_ascii=False))
        result = subprocess.run(
            [str(binary), str(root), str(script), str(trace)],
            env=env,
            capture_output=True,
            timeout=60,
        )
        (output / (stage + ".log")).write_bytes(result.stdout + result.stderr)
        events = [json.loads(line) for line in trace.read_text().splitlines()]
        assert result.returncode == 0, (
            stage,
            result.returncode,
            events[-1].get("step"),
        )
        assert events[-1]["closed"] and events[-1]["step"] == len(steps), stage
        assert not any(
            token in result.stderr
            for token in (b"ReferenceError", b"TypeError", b"Binding loop detected")
        )
        owners.append(inspect())
        return events

    def open_rules(when: dict) -> list[dict]:
        return [
            button("settingsButton", when=dict(when, ephemeral=False)),
            button("settingsRoutingButton"),
        ]

    def exit_step(policy: dict, revision: int, **extra: object) -> dict:
        return ui(
            "quit",
            when=dict(ready=True, routing=policy, routing_revision=revision, **extra),
        )

    first = launch(
        "save",
        [
            *open_rules({"ready": True}),
            command(
                dict(
                    command="maintenance_start",
                    request_id=91,
                    operation="backup",
                    destination=str(root / "copies/schema3.sqlite"),
                    revision=0,
                )
            ),
            command(
                dict(
                    command="edit_routing",
                    request_id=101,
                    expected_revision=0,
                    create=True,
                    confirm_broad=False,
                    rule=mixed,
                ),
                {
                    "maintenance_ack": {
                        "request_id": 91,
                        "phase": "complete",
                        "error": None,
                    }
                },
            ),
            command(
                dict(
                    command="edit_routing",
                    request_id=102,
                    expected_revision=1,
                    create=True,
                    confirm_broad=False,
                    rule=other,
                ),
                {"routing_revision": 1},
            ),
            button("routingUp42", when={"routing": initial, "routing_revision": 2}),
            button(
                "routingEdit41",
                when={"routing": ordered, "routing_revision": 3},
            ),
            button(
                "routingModeButton",
                expect=simple_fields,
                when={"routing": ordered, "routing_revision": 3},
            ),
            button(
                "routingModeButton",
                expect=advanced_fields,
                when={"routing": ordered, "routing_revision": 3},
            ),
            button(
                "routingSaveRule",
                expect=simple_fields,
                when={"routing": ordered, "routing_revision": 3},
            ),
            exit_step(
                ordered, 4, routing_ack={"request_id": 2, "saved_id": 41, "error": None}
            ),
        ],
    )
    second = launch(
        "fresh-negative",
        [
            *open_rules({"ready": True, "routing": ordered, "routing_revision": 4}),
            button("routingRulesTab"),
            button("routingEdit41"),
            button("routingEnabled", expect=fields),
            button("routingSaveRule", expect={"routingEnabled": {"checked": True}}),
            command(
                {"command": "connect"},
                {
                    "routing": active,
                    "routing_revision": 5,
                    "routing_ack": {"request_id": 1, "saved_id": 41, "error": None},
                },
            ),
            exit_step(active, 5, error="unsupported_option", can_stop=False),
        ],
    )
    third = launch(
        "fresh-final",
        [
            *open_rules({"ready": True, "routing": active, "routing_revision": 5}),
            button("routingRulesTab"),
            button("routingEdit41"),
            button("routingModeButton", expect=simple_fields),
            button("routingModeButton", expect=advanced_fields),
            ui("key", "routingModeButton", key="Tab", expect=simple_fields),
            exit_step(active, 5),
        ],
    )
    assert first and second and third
    assert len(owners) == 3 and owners[0] == owners[1] == owners[2]
    assert owners[0]["items"].startswith("ao 1 ")
    return {
        "passed": True,
        "processes": 3,
        "disabled_saved_revision": 4,
        "enabled_saved_revision": 5,
        "activation_error": "unsupported_option",
        "ordered_disabled": ordered,
        "ordered_enabled": active,
        "owners": owners,
        "oracle": "exact snapshot conditions in scripts; production driver completion gates",
    }


def run(binary: Path, output: Path) -> None:
    """Проверить нормальный цикл и закрыть только собственные процессы."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    processes: list[subprocess.Popen] = []
    with tempfile.TemporaryDirectory(prefix="p07-persistence-") as temporary:
        root = Path(temporary)
        nonce = os.urandom(16).hex()
        (root / "nonce").write_text(nonce)
        for directory in ("copies", "data"):
            (root / directory).mkdir(mode=0o700)
        env = dict(
            PATH=os.defpath,
            LANG="C.UTF-8",
            HOME=temporary,
            XDG_RUNTIME_DIR=temporary,
            XDG_DATA_HOME=temporary + "/data",
            XDG_CONFIG_HOME=temporary + "/config",
            XDG_CACHE_HOME=temporary + "/cache",
            QT_QPA_PLATFORM="offscreen",
            QT_FORCE_STDERR_LOGGING="1",
            QT_QUICK_BACKEND="software",
            QT_QUICK_CONTROLS_STYLE="Basic",
            P06_PRIVATE_NONCE=nonce,
        )
        config = root / "bus.conf"
        config.write_text(
            "<busconfig><type>session</type><listen>unix:tmpdir="
            + temporary
            + '</listen><policy context="default"><allow send_destination="*"/>'
            '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>'
        )
        records: dict = {
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()
        }

        def call(*args: str) -> str:
            return subprocess.check_output(
                ["busctl", "--address=" + address, *args],
                env=env,
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
            ).strip()

        def inspect() -> dict:
            pid = call(
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixProcessID",
                "s",
                "org.freedesktop.secrets",
            )
            uid = call(
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixUser",
                "s",
                "org.freedesktop.secrets",
            )
            assert (
                pid == f"u {daemon.pid}"
                and uid == f"u {os.getuid()}"
                and daemon.poll() is None
            )
            collection = call(
                "call",
                "org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
                "ReadAlias",
                "s",
                "default",
            ).split('"')[1]
            items = call(
                "get-property",
                "org.freedesktop.secrets",
                collection,
                "org.freedesktop.Secret.Collection",
                "Items",
            )
            locked = call(
                "get-property",
                "org.freedesktop.secrets",
                collection,
                "org.freedesktop.Secret.Collection",
                "Locked",
            )
            assert locked == "b false"
            return {
                "owner_pid": daemon.pid,
                "owner_uid": os.getuid(),
                "collection": collection,
                "items": items,
                "locked": False,
                "attributes": [
                    call(
                        "get-property",
                        "org.freedesktop.secrets",
                        item,
                        "org.freedesktop.Secret.Item",
                        "Attributes",
                    )
                    for item in items.split(chr(34))[1::2]
                ],
            }

        try:
            bus = subprocess.Popen(
                [
                    "dbus-daemon",
                    "--nofork",
                    "--print-address=1",
                    "--config-file=" + str(config),
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            processes.append(bus)
            with selectors.DefaultSelector() as selector:
                selector.register(bus.stdout, selectors.EVENT_READ)
                assert selector.select(5)
            address = bus.stdout.readline().decode().strip()
            env.update(
                DBUS_SESSION_BUS_ADDRESS=address, DBUS_SYSTEM_BUS_ADDRESS=address
            )
            assert (
                call(
                    "call",
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "NameHasOwner",
                    "s",
                    "org.freedesktop.secrets",
                )
                == "b false"
            )
            records["name_absent_before"] = True
            key_read, key_write = os.pipe()
            with (
                socket.socket(socket.AF_UNIX) as listener,
                (output / "daemon.log").open("wb") as log,
            ):
                listener.bind(temporary + "/environment")
                listener.listen(1)
                daemon = subprocess.Popen(
                    ["ksecretd", "--pam-login", str(key_read), str(listener.fileno())],
                    env=env | {"PAM_KWALLET5_LOGIN": "1"},
                    pass_fds=(key_read, listener.fileno()),
                    stdout=log,
                    stderr=log,
                )
                processes.append(daemon)
                os.close(key_read)
                os.write(key_write, os.urandom(56))
                os.close(key_write)
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.connect(temporary + "/environment")
                deadline = time.monotonic() + 5
                while True:
                    try:
                        records["before"] = inspect()
                        break
                    except subprocess.CalledProcessError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                assert records["before"]["items"] == "ao 0"
                records["gui"] = gui_campaign(binary, root, output, env, inspect)
                records["after"] = inspect()
                assert records["after"]["items"].startswith("ao 1 ")
                records["stages_passed"] = True
        finally:
            try:
                if len(processes) == 2 and processes[0].poll() is None:
                    daemon.terminate()
                    daemon.wait(timeout=5)
                    records["name_absent_after"] = (
                        call(
                            "call",
                            "org.freedesktop.DBus",
                            "/org/freedesktop/DBus",
                            "org.freedesktop.DBus",
                            "NameHasOwner",
                            "s",
                            "org.freedesktop.secrets",
                        )
                        == "b false"
                    )
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
                records["owned_processes_closed"] = all(
                    process.poll() is not None for process in processes
                )
                (output / "result.json").write_text(
                    json.dumps(records, indent=2) + "\n"
                )
        assert records.get("stages_passed") and records.get("name_absent_after")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.output.resolve())
