#!/usr/bin/env python3
"""Частная X11 campaign: неизменяемый runtime, owned sessions, явный terminal."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import os
import platform
import runpy
import select
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
legacy = importlib.import_module("ui_benchmark")

PROBE = runpy.run_path(str(ROOT / "bench/ui/private-x11-preflight.py"))
CONTRACT = dict(
    repetitions=3,
    rows=[1000, 10000],
    toolkits=["qt", "gtk", "slint"],
    visible_seconds=900,
    hidden_seconds=900,
    sample_seconds=5,
    cell_seconds=2100,
    cleanup_seconds=10,
    ack_seconds=15,
)
DEFINITIONS = dict(
    qt="QQuickWindow.frameSwapped",
    gtk="GdkFrameClock.after-paint: paint cycle, not presentation",
    slint="RenderingState.AfterRendering",
)


class CoverageError(legacy.BenchmarkError):
    """Обнаружен процесс вне учтённой process-only метрики."""


class Cancelled(legacy.BenchmarkError):
    """Отмена или исчерпанный cell budget."""


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def subreaper() -> None:
    # Локальное свойство supervisor: позволяет reap своих осиротевших descendants.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")


def proc_stat(pid: int) -> dict:
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rindex(")") + 2 :].split()
    return dict(
        pid=pid,
        state=fields[0],
        ppid=int(fields[1]),
        pgid=int(fields[2]),
        sid=int(fields[3]),
        start_ticks=int(fields[19]),
    )


def identity(pid: int) -> dict:
    before = proc_stat(pid)
    root = Path(f"/proc/{pid}")
    namespaces = {
        name: os.readlink(root / "ns" / name)
        for name in ("pid", "user", "mnt", "net", "ipc", "uts")
    }
    executable = root / "exe"
    stat = executable.stat()
    after = proc_stat(pid)
    if any(before[k] != after[k] for k in ("start_ticks", "pgid", "sid")):
        raise CoverageError("Identity изменилась во время чтения")
    return dict(
        pid=pid,
        start_ticks=before["start_ticks"],
        pgid=before["pgid"],
        sid=before["sid"],
        namespaces=namespaces,
        exe=os.readlink(executable),
        exe_device=stat.st_dev,
        exe_inode=stat.st_ino,
    )


def exited(pidfd: int) -> bool:
    return bool(select.select([pidfd], [], [], 0)[0])


class ProcessGuard:
    """PID резервируется до последних group signals; pidfd удерживается до reap."""

    def __init__(self, process: subprocess.Popen) -> None:
        self.process = process
        self.pidfd: int | None = None
        self.identity: dict = {}
        self.tracked: dict[int, int] = {}
        self.observed_descendants: set[int] = set()
        self.descendant_receipts: dict[int, dict] = {}
        self.cleanup: dict = {}
        self.closed = False
        try:
            self.pidfd = os.pidfd_open(process.pid)
            self.identity = identity(process.pid)
            if (
                self.identity["pgid"] != process.pid
                or self.identity["sid"] != process.pid
            ):
                raise CoverageError("Child не владеет новой session/process group")
            self.verify()
        except BaseException:
            # Даже ошибка namespace/metadata после Popen не оставляет процесс.
            self.close()
            raise

    def verify(self) -> None:
        if self.closed or self.pidfd is None or exited(self.pidfd):
            raise CoverageError("Child pidfd завершён")
        if identity(self.process.pid) != self.identity:
            raise CoverageError(
                "PID/start/namespace/group/executable identity mismatch"
            )

    def discover(self) -> list[int]:
        leader = self.process.pid
        found: set[int] = set()

        def pin(pid: int, parent: int | None = None) -> bool:
            if pid in self.tracked:
                return not exited(self.tracked[pid])
            fd = None
            try:
                # Сначала pidfd, затем проверка текущей ownership: PID из /proc
                # мог исчезнуть/переиспользоваться до открытия fd. Для ancestry
                # parent pidfd повторно проверяется ПОСЛЕ pin/read child: иначе
                # exit/reuse числового parent PID мог бы приписать чужой child.
                fd = os.pidfd_open(pid)
                stat = proc_stat(pid)
                if Path(f"/proc/{pid}").stat().st_uid != os.getuid():
                    return False
                parent_fd = self.pidfd if parent == leader else self.tracked.get(parent)
                owned = (
                    stat["sid"] == leader
                    if parent is None
                    else (
                        stat["ppid"] == parent
                        and parent_fd is not None
                        and not exited(parent_fd)
                    )
                )
                if not owned:
                    return False
                self.tracked[pid] = fd
                self.descendant_receipts[pid] = dict(
                    stat, ownership="owned session or pinned parent ancestry"
                )
                fd = None
                return True
            except ProcessLookupError:
                return False
            finally:
                if fd is not None:
                    os.close(fd)

        for path in Path("/proc").iterdir():
            if not path.name.isdecimal():
                continue
            try:
                if path.stat().st_uid != os.getuid():
                    continue
                stat = proc_stat(int(path.name))
                if stat["sid"] == leader and stat["pid"] != leader:
                    found.add(stat["pid"])
                    pin(stat["pid"])
            except (OSError, ValueError, IndexError):
                continue
        pending = [leader]
        visited: set[int] = set()
        while pending:
            parent = pending.pop()
            if parent in visited:
                continue
            visited.add(parent)
            fd = self.pidfd if parent == leader else self.tracked.get(parent)
            if fd is None or exited(fd):
                continue
            for path in Path(f"/proc/{parent}/task").glob("*/children"):
                try:
                    children = [int(value) for value in path.read_text().split()]
                except OSError:
                    continue
                found.update(children)
                for pid in children:
                    if pin(pid, parent):
                        pending.append(pid)
        self.observed_descendants.update(found)
        return sorted(found)

    def sample(self) -> dict:
        self.verify()
        descendants = self.discover()
        if descendants:
            raise CoverageError(f"Неучтённые descendants: {descendants}")
        root = Path(f"/proc/{self.process.pid}")
        started = time.monotonic_ns()
        metrics = legacy.parse_proc(
            (root / "stat").read_text(),
            (root / "status").read_text(),
            (root / "smaps_rollup").read_text(),
        )
        self.verify()
        metrics.update(
            pid=self.process.pid,
            start_ticks=self.identity["start_ticks"],
            monotonic_ns=time.monotonic_ns(),
            read_started_ns=started,
            clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
            wakeups=None,
            gpu=None,
            hardware_power=None,
            observed_descendants=[],
        )
        return metrics

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        deadline = time.monotonic() + 10
        errors = []
        group_reserved = False

        def census() -> None:
            try:
                self.discover()
            except Exception as error:
                # Ошибка наблюдения запрещает COMPLETE, но не завершение группы.
                errors.append(f"cleanup census: {error}")

        def reap_group() -> None:
            if not group_reserved:
                return
            while True:
                try:
                    pid, _ = os.waitpid(-self.process.pid, os.WNOHANG)
                except ChildProcessError:
                    return
                if pid:
                    continue
                if time.monotonic() >= deadline:
                    errors.append("owned group reap deadline")
                    return
                time.sleep(0.01)

        try:
            # WNOWAIT подтверждает, что direct child не reap внешним кодом.
            os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            stat = proc_stat(self.process.pid)
            group_reserved = (
                stat["pgid"] == self.process.pid and stat["sid"] == self.process.pid
            )
            if self.identity and stat["start_ticks"] != self.identity["start_ticks"]:
                group_reserved = False
                errors.append("start identity lost")
            if self.identity and self.pidfd is not None and not exited(self.pidfd):
                if identity(self.process.pid) != self.identity:
                    group_reserved = False
                    errors.append("live namespace/executable identity mismatch")
            census()
            for number in (signal.SIGTERM, signal.SIGKILL):
                if group_reserved:
                    try:
                        os.killpg(self.process.pid, number)
                    except ProcessLookupError:
                        pass
                for fd in [self.pidfd, *self.tracked.values()]:
                    if fd is not None and not exited(fd):
                        try:
                            signal.pidfd_send_signal(fd, number)
                        except ProcessLookupError:
                            pass
                if number == signal.SIGTERM:
                    # Не reap leader до KILL: числовой PGID остаётся зарезервирован.
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
                    census()
            if self.pidfd is not None:
                while not exited(self.pidfd) and time.monotonic() < deadline:
                    select.select(
                        [self.pidfd],
                        [],
                        [],
                        min(0.1, max(0, deadline - time.monotonic())),
                    )
            # Последний census до reap leader сохраняет reservation числового SID.
            census()
            for fd in self.tracked.values():
                if not exited(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
            reap_group()
            reaped = []
            for pid, fd in self.tracked.items():
                while not exited(fd) and time.monotonic() < deadline:
                    select.select(
                        [fd], [], [], min(0.1, max(0, deadline - time.monotonic()))
                    )
                try:
                    status = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if status is not None:
                        reaped.append(pid)
                except ChildProcessError:
                    # Не-direct child мог быть reap исходным родителем до его exit.
                    if Path(f"/proc/{pid}").exists():
                        errors.append(f"descendant not reaped: {pid}")
                if Path(f"/proc/{pid}").exists():
                    errors.append(f"descendant proc remains: {pid}")
            self.cleanup = dict(
                reaped=self.process.returncode is not None,
                proc_absent=not Path(f"/proc/{self.process.pid}").exists(),
                returncode=self.process.returncode,
                descendants_reaped=reaped,
                group_reserved_until_kill=group_reserved,
                errors=errors,
            )
        except BaseException as error:
            errors.append(str(error))
            # После wait leader reservation уже освобождена; PGID нельзя трогать.
            if group_reserved and self.process.returncode is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            # pidfd остаётся безопасным адресатом даже при испорченном metadata.
            for fd in [self.pidfd, *self.tracked.values()]:
                if fd is not None and not exited(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            try:
                self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                errors.append("cleanup deadline")
            reap_group()
            self.cleanup = dict(
                reaped=self.process.returncode is not None, errors=errors
            )
        finally:
            self.cleanup["observed_descendants"] = sorted(self.observed_descendants)
            self.cleanup["descendant_receipts"] = self.descendant_receipts
            for fd in [self.pidfd, *self.tracked.values()]:
                if fd is not None:
                    os.close(fd)
        if (
            errors
            or not self.cleanup.get("reaped")
            or not self.cleanup.get("proc_absent", False)
        ):
            raise CoverageError(f"Неполный cleanup: {self.cleanup}")


class TrackedChild(legacy.Child):
    def __init__(self, argv: list[str], stderr_path: Path) -> None:
        self.guard: ProcessGuard | None = None
        super().__init__(argv, stderr_path)
        try:
            self.guard = ProcessGuard(self.process)
        except BaseException:
            self._streams_close()
            raise

    def sample(self) -> dict:
        if self.guard is None:
            raise CoverageError("Guard отсутствует")
        return self.guard.sample()

    def _streams_close(self) -> None:
        if self.selector is not None:
            self.selector.close()
        for stream in (
            self.process.stdin,
            self.process.stdout,
            self.process.stderr,
            self.log,
        ):
            if stream:
                stream.close()

    def close(self) -> None:
        if self.guard is None:
            # super().__init__ мог вызвать close до создания guard.
            super().close()
            return
        if self.stopped:
            return
        try:
            self.guard.close()
        finally:
            self.stopped = True
            self._streams_close()

    def finish(self, timeout: float) -> None:
        # Reap/cleanup только в cell finally после выключения cell alarm.
        deadline = time.monotonic() + timeout
        while self.exit_code() is None:
            if time.monotonic() >= deadline:
                raise legacy.BenchmarkError("Timeout завершения Quit")
            self.pump(min(0.1, max(0, deadline - time.monotonic())))
        while (
            self.selector is not None
            and self.selector.get_map()
            and time.monotonic() < deadline
        ):
            self.pump(min(0.1, max(0, deadline - time.monotonic())))
        if self.pending or self.buffer or self.exit_code() != 0:
            raise legacy.BenchmarkError("Некорректный exit/лишний ack после Quit")


def conditions() -> dict:
    builds = []
    for path in Path("/proc").iterdir():
        try:
            if path.name.isdecimal() and path.stat().st_uid == os.getuid():
                name = (path / "comm").read_text().strip()
                if name in (
                    "cargo",
                    "rustc",
                    "cc1",
                    "cc1plus",
                    "clang",
                    "clang++",
                    "ld",
                    "ld.lld",
                    "mold",
                ):
                    builds.append(dict(pid=int(path.name), comm=name))
        except OSError:
            continue
    return dict(
        utc=datetime.now(timezone.utc).isoformat(),
        monotonic_ns=time.monotonic_ns(),
        loadavg=os.getloadavg(),
        uname=list(platform.uname()),
        observed_same_uid_builds=builds,
        build_scan_scope="same uid comm snapshots only",
        other_work="P02/other workers may cause noise; not modified",
        gpu=None,
        hardware_power=None,
        environment={
            key: os.environ.get(key)
            for key in (
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XDG_SESSION_TYPE",
                "QT_QPA_PLATFORM",
                "QT_QUICK_BACKEND",
                "GDK_BACKEND",
                "GSK_RENDERER",
                "LIBGL_ALWAYS_SOFTWARE",
                "GALLIUM_DRIVER",
                "PATH",
            )
        },
    )


class Supervisor:
    def __init__(self, output: Path, expected_cells: int = 18) -> None:
        subreaper()
        self.output = output
        output.mkdir(parents=True, exist_ok=False)
        self.binding: dict = {}
        self.expected_cells = expected_cells
        self.completed_cells = 0
        self.owned: list[Any] = []
        self.receipt = dict(
            event="exec_session_receipt",
            identity=identity(os.getpid()),
            cwd=os.getcwd(),
            argv=sys.argv,
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            conditions=conditions(),
        )
        atomic_json(output / "receipt.json", self.receipt)
        self.self_pidfd = os.pidfd_open(os.getpid())
        self.cleaning = False
        self.pending_signal: int | None = None
        self.handlers: dict = {}

    def __enter__(self) -> Supervisor:
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            self.handlers[number] = signal.signal(number, self.receive)
        return self

    def receive(self, number: int, _frame: Any) -> None:
        self.pending_signal = number
        if not self.cleaning:
            raise Cancelled(f"Сигнал/таймаут: {number}")

    def own(self, child: Any) -> Any:
        self.owned.append(child)
        return child

    def spawn(self, factory: Any) -> Any:
        self.cleaning = True
        try:
            return self.own(factory())
        finally:
            self.cleaning = False
            if self.pending_signal:
                raise Cancelled(f"Отмена после spawn: {self.pending_signal}")

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> bool:
        signal.setitimer(signal.ITIMER_REAL, 0)
        self.cleaning = True
        cleanups = []
        errors = []
        for resource in reversed(self.owned):
            try:
                resource.close()
            except BaseException as error:
                errors.append(str(error))
            guard = resource.guard if isinstance(resource, TrackedChild) else resource
            cleanups.append(dict(identity=guard.identity, cleanup=guard.cleanup))
        complete = (
            kind is None
            and not errors
            and self.completed_cells == self.expected_cells
            and not self.pending_signal
        )
        terminal = dict(
            event="terminal",
            state="COMPLETE" if complete else "FAILED",
            receipt_sha256=sha(self.output / "receipt.json"),
            completed_cells=self.completed_cells,
            expected_cells=self.expected_cells,
            run_binding=self.binding,
            error=None if value is None else repr(value),
            cleanup_errors=errors,
            cleanups=cleanups,
            conditions=conditions(),
        )
        try:
            atomic_json(self.output / "terminal.json", terminal)
        finally:
            os.close(self.self_pidfd)
            for number, handler in self.handlers.items():
                signal.signal(number, handler)
        if kind is None and not complete:
            raise CoverageError(f"Campaign не COMPLETE: {terminal['error']}, {errors}")
        return False


def verify_snapshot(expected: str) -> dict:
    path = ROOT / "manifest.json"
    if sha(path) != expected:
        raise CoverageError("Snapshot manifest SHA mismatch")
    if path.stat().st_mode & 0o222 or ROOT.stat().st_mode & 0o222:
        raise CoverageError("Snapshot root/manifest writable")
    data = json.loads(path.read_text())
    if data["contract"] != CONTRACT or data["frame_definitions"] != DEFINITIONS:
        raise CoverageError("Несовпадение source-bound phase contract")
    required = {
        "bench/ui/campaign/runner.py",
        "tools/ui_benchmark.py",
        "tools/resource_counters.py",
        "bench/ui/private-x11-preflight.py",
        "bin/Xvfb",
        "provenance/native-manifest.json",
        "provenance/xvfb-runtime-inputs.json",
        "provenance/create_snapshot.py",
        *[f"bin/yonik-bench-{toolkit}" for toolkit in CONTRACT["toolkits"]],
    }
    if len(data["native_inputs"]) != 17 or set(data["files"]) != required | set(
        data["native_inputs"]
    ):
        raise CoverageError("Неполный snapshot closure")
    for relative, digest in data["files"].items():
        target = ROOT / relative
        if (
            not target.resolve().is_relative_to(ROOT)
            or target.is_symlink()
            or not target.is_file()
        ):
            raise CoverageError("Snapshot path escape")
        if any(
            parent.stat().st_mode & 0o222
            for parent in target.parents
            if parent.is_relative_to(ROOT)
        ):
            raise CoverageError("Snapshot directory writable")
        if target.stat().st_mode & 0o222 or sha(target) != digest:
            raise CoverageError(f"Неизменяемый snapshot input изменён: {relative}")
    for absolute, digest in data["host_inputs"].items():
        if not Path(absolute).is_absolute() or not str(
            Path(absolute).resolve()
        ).startswith("/usr/"):
            raise CoverageError("Host input вне trusted /usr")
        if sha(Path(absolute)) != digest:
            raise CoverageError(f"Host input изменён: {absolute}")
    return data


def audit_references(pids: list[int], forbidden: str) -> dict:
    hits = []
    for pid in pids:
        root = Path(f"/proc/{pid}")
        for path in [root / "cwd", root / "exe", *list((root / "fd").iterdir())]:
            try:
                target = os.readlink(path)
            except FileNotFoundError:
                continue
            if target.startswith(forbidden):
                hits.append(dict(pid=pid, surface=str(path), target=target))
        if forbidden in (root / "maps").read_text():
            hits.append(dict(pid=pid, surface="maps"))
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and str(path).startswith(forbidden):
            hits.append(dict(module=name, source=path))
    for function in (
        PROBE["validate_counter"],
        PROBE["require_canary"],
        legacy.Oracle.validate,
        cell,
    ):
        if function.__code__.co_filename.startswith(forbidden):
            hits.append(
                dict(surface="python code source", source=function.__code__.co_filename)
            )
    if any(str(path).startswith(forbidden) for path in sys.path):
        hits.append(dict(surface="sys.path"))
    if hits:
        raise CoverageError(f"Mutable worktree references: {hits}")
    return dict(
        verified_no_references=True,
        forbidden=forbidden,
        pids=pids,
        surfaces=[
            "cwd",
            "exe",
            "fd",
            "maps",
            "sys.modules.__file__",
            "sys.path",
            "python code source",
        ],
        monotonic_ns=time.monotonic_ns(),
    )


def start_xvfb(supervisor: Supervisor) -> ProcessGuard:
    read_fd, write_fd = os.pipe()
    guard = None
    try:
        with (supervisor.output / "xvfb.stderr").open("xb") as log:
            guard = supervisor.spawn(
                lambda: ProcessGuard(
                    subprocess.Popen(
                        [
                            str(ROOT / "bin/Xvfb"),
                            "-displayfd",
                            str(write_fd),
                            "-screen",
                            "0",
                            "1024x768x24",
                            "-nolisten",
                            "tcp",
                            "-ac",
                            "-noreset",
                        ],
                        pass_fds=(write_fd,),
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                        start_new_session=True,
                    )
                )
            )
        os.close(write_fd)
        write_fd = -1
        if not select.select([read_fd], [], [], 10)[0]:
            raise CoverageError("Xvfb displayfd timeout")
        display = os.read(read_fd, 64).decode().strip()
        if not display.isdecimal():
            raise CoverageError("Xvfb displayfd malformed")
        os.environ["DISPLAY"] = ":" + display
        return guard
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def sample_idle(
    child: TrackedChild,
    sidecar: ProcessGuard | None,
    duration: float,
    interval: float,
    samples: list,
    started: float | None = None,
) -> None:
    """Только stdout readiness и /proc; stdin/Probe здесь отсутствуют."""
    if started is None:
        started = time.monotonic()
    next_sample = started
    while True:
        now = time.monotonic()
        if now >= next_sample:
            sample = child.sample()
            sample["conditions"] = conditions()
            samples.append(sample)
            if sidecar is not None:
                sidecar.verify()
            next_sample += interval
        if now >= started + duration:
            break
        child.pump(max(0, min(next_sample, started + duration) - time.monotonic()))
        child.alive()
        if child.pending or child.buffer:
            raise CoverageError("Незапрошенный stdout во время idle")


def cell(
    supervisor: Supervisor,
    xvfb: ProcessGuard,
    metadata: dict,
    rep: int,
    rows: int,
    toolkit: str,
    short: bool,
) -> None:
    output = supervisor.output / f"rep{rep}-{toolkit}-{rows}"
    output.mkdir()
    record = dict(
        repetition=rep,
        rows=rows,
        toolkit=toolkit,
        valid=False,
        actions=[],
        probes=[],
        phases=[],
    )
    child = None
    deadline = time.monotonic() + (30 if short else 2100)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
    try:
        binary = ROOT / f"bin/yonik-bench-{toolkit}"
        if sha(binary) != metadata["files"][str(binary.relative_to(ROOT))]:
            raise CoverageError("ELF SHA mismatch перед exec")
        child = supervisor.spawn(
            lambda: TrackedChild(
                [str(binary), "--rows", str(rows)], output / "stderr.log"
            )
        )
        record["identity"] = child.guard.identity
        record["reference_audit"] = audit_references(
            [os.getpid(), xvfb.process.pid, child.process.pid],
            metadata["origin_worktree"],
        )
        if not (supervisor.output / "ready.json").exists():
            atomic_json(
                supervisor.output / "ready.json",
                dict(
                    event="snapshot_ready",
                    receipt_sha256=sha(supervisor.output / "receipt.json"),
                    manifest_sha256=sha(ROOT / "manifest.json"),
                    reference_audit=record["reference_audit"],
                    process_identity=supervisor.receipt["identity"],
                ),
            )
        oracle = legacy.Oracle(rows)
        report, _ = child.ack(15)
        oracle.validate(report, "frame")
        record["initial_report"] = report
        record["process_cold_start_ms"] = (time.monotonic_ns() - child.spawn_ns) / 1e6
        nonce = 0
        counter = 0

        def action(command: dict, label: str) -> None:
            event = oracle.apply(command)
            started = child.send(command, 15)
            report, received = child.ack(15)
            oracle.validate(report, event)
            if report["toolkit"] != toolkit:
                raise CoverageError("Toolkit mismatch")
            record["actions"].append(
                dict(
                    command=command,
                    label=label,
                    report=report,
                    latency_ms=(received - started) / 1e6,
                )
            )
            child.sample()

        def probe(label: str) -> int:
            nonlocal nonce, counter
            nonce += 1
            sent = child.send(dict(op="probe", nonce=nonce), 15)
            report, received = child.ack(15)
            counter = PROBE["validate_counter"](report, nonce, counter)
            oracle.validate(
                {
                    key: value
                    for key, value in report.items()
                    if key not in ("nonce", "rendered_frames")
                },
                "probe",
            )
            if report["toolkit"] != toolkit:
                raise CoverageError("Probe toolkit mismatch")
            record["probes"].append(
                dict(label=label, sent_ns=sent, received_ns=received, report=report)
            )
            return counter

        before = probe("sensitivity-A")
        action(dict(op="scroll", index=199), "sensitivity-scroll")
        after = probe("sensitivity-B")
        PROBE["require_canary"](before, after)
        # Только sensitivity/phase boundaries: нет Probe на каждом search/action.
        for command, label in (
            (legacy.query(), "page"),
            (legacy.query("server-0.example.invalid"), "cold-search"),
            (legacy.query("server-0.example.invalid"), "warm-search"),
            (dict(op="select", id=1), "select"),
            (dict(op="favorite", id=1, value=True), "favorite"),
            (legacy.query(favorites_only=True), "filter"),
            (legacy.query(), "reset"),
            (legacy.query(sort="name"), "sort"),
            (dict(op="scroll", index=199), "scroll"),
        ):
            action(command, label)

        def phase(name: str) -> None:
            frames_before = probe(name + "-start")
            started = time.monotonic()
            duration = 0.15 if short else 900
            interval = 0.05 if short else 5
            phase_record = dict(
                name=name,
                requested_seconds=duration,
                start_ns=time.monotonic_ns(),
                frames_before=frames_before,
                samples=[],
                conditions_start=conditions(),
            )
            record["phases"].append(phase_record)
            sample_idle(
                child, xvfb, duration, interval, phase_record["samples"], started
            )
            phase_record["end_ns"] = time.monotonic_ns()
            phase_record["frames_after"] = probe(name + "-end")
            phase_record["frame_delta"] = phase_record["frames_after"] - frames_before
            phase_record["conditions_end"] = conditions()

        phase("visible")
        action(dict(op="hide"), "hide")
        phase("hidden")
        action(dict(op="show"), "show")
        child.send(dict(op="quit"), 15)
        child.finish(min(15, max(0.01, deadline - time.monotonic())))
        record["protocol_valid"] = True
    except BaseException as error:
        record["error"] = repr(error)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        supervisor.cleaning = True
        try:
            if child is not None:
                child.close()
                record["cleanup"] = child.guard.cleanup
                if child.guard.observed_descendants:
                    raise CoverageError(
                        "Descendants наблюдались вне измеряемого leader: cell invalid"
                    )
                if record.get("protocol_valid"):
                    record["valid"] = True
                    supervisor.completed_cells += 1
        except BaseException as error:
            record["valid"] = False
            record["error"] = repr(error)
            raise
        finally:
            supervisor.cleaning = False
            atomic_json(output / "cell.json", record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--mode", choices=("short", "campaign"), default="short")
    args = parser.parse_args()
    os.chdir(ROOT)
    supervisor = Supervisor(args.output.resolve())
    try:
        with supervisor:
            metadata = verify_snapshot(args.manifest_sha256)
            if supervisor.output.is_relative_to(
                metadata["origin_worktree"]
            ) or supervisor.output.is_relative_to("/var/tmp/codex-myrs/transient"):
                raise CoverageError("Output должен быть вне mutable worktree и TTL")
            supervisor.binding = dict(
                manifest_sha256=args.manifest_sha256,
                mode=args.mode,
                contract=CONTRACT,
                actual_idle_seconds=0.15 if args.mode == "short" else 900,
                sample_seconds=0.05 if args.mode == "short" else 5,
            )
            atomic_json(
                supervisor.output / "binding.json",
                dict(
                    manifest_sha256=args.manifest_sha256,
                    mode=args.mode,
                    contract=CONTRACT,
                    frame_definitions=DEFINITIONS,
                    measurement_scope="candidate process only; Xvfb excluded; not physical energy",
                    descendant_limit="FAIL on observed descendants; transient fork/exit between scans can be missed",
                    frame_window="raw Probe send/ack boundaries include measurement overhead; no settling subtraction",
                ),
            )
            for key in (
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "QT_PLUGIN_PATH",
                "QT_QPA_PLATFORM_PLUGIN_PATH",
                "QML_IMPORT_PATH",
                "QML2_IMPORT_PATH",
                "GIO_EXTRA_MODULES",
                "GTK_PATH",
                "GTK_MODULES",
                "SLINT_BACKEND",
            ):
                os.environ.pop(key, None)
            os.environ.update(
                PATH="/usr/bin",
                XDG_SESSION_TYPE="x11",
                QT_QPA_PLATFORM="xcb",
                QT_QUICK_BACKEND="software",
                GDK_BACKEND="x11",
                GSK_RENDERER="cairo",
                GTK_A11Y="none",
                LIBGL_ALWAYS_SOFTWARE="1",
                GALLIUM_DRIVER="llvmpipe",
                MESA_LOADER_DRIVER_OVERRIDE="llvmpipe",
                WINIT_UNIX_BACKEND="x11",
            )
            os.environ.pop("WAYLAND_DISPLAY", None)
            xvfb = start_xvfb(supervisor)
            for repetition in range(1, 4):
                for rows in CONTRACT["rows"]:
                    for toolkit in CONTRACT["toolkits"]:
                        cell(
                            supervisor,
                            xvfb,
                            metadata,
                            repetition,
                            rows,
                            toolkit,
                            args.mode == "short",
                        )
            verify_snapshot(args.manifest_sha256)
        return 0
    except BaseException as error:
        sys.stderr.write(f"Campaign FAILED: {error!r}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
