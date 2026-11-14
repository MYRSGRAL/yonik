#!/usr/bin/env python3
"""Офлайн-кандидат N5; доверие к квитанции устанавливает вызывающая сторона."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

POLICY = "yonik-own-namespace-fixed16-v1"
ABI = "linux-native-abi260-ynkch004-ynkns004-v1"
FROZEN_CONTROL = "bd5d7474108a2a1e051734ea4c9097d43380341025ed9cd60e0f1442527d2983"
MAX_METADATA = 4096
MAX_ELF = 128 * 1024 * 1024
MAX_SOURCE = 512 * 1024 * 1024


def stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
    )


def open_regular(path: Path) -> int:
    """Не следовать symlink ни в одном компоненте пути, не блокироваться на FIFO."""
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        result = os.open(
            absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
        )
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise ValueError("Требуется обычный файл")
        return result
    finally:
        os.close(fd)


def read_artifact(
    path: Path, limit: int, elf: bool = False, collect: bool = False
) -> tuple[str, bytes]:
    fd = open_regular(path)
    try:
        before = stamp(os.fstat(fd))
        if not 0 < before[2] <= limit:
            raise ValueError("Размер файла вне границ")
        digest = hashlib.sha256()
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            if total == 0 and elf and not chunk.startswith(b"\x7fELF"):
                raise ValueError("Нет ELF magic")
            total += len(chunk)
            if total > limit:
                raise ValueError("Превышен предел чтения")
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
        if total != before[2] or stamp(os.fstat(fd)) != before:
            raise ValueError("Файл изменился при чтении")
        # Повторная безопасная проверка pathname обнаруживает подмену inode.
        check = open_regular(path)
        try:
            if stamp(os.fstat(check)) != before:
                raise ValueError("Путь подменён при чтении")
        finally:
            os.close(check)
        return digest.hexdigest(), b"".join(chunks)
    finally:
        os.close(fd)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повторное поле JSON")
        result[key] = value
    return result


def read_data(path: Path, fields: set[str]) -> dict[str, object]:
    _, raw = read_artifact(path, MAX_METADATA, collect=True)
    value = json.loads(
        raw, object_pairs_hook=unique_object, parse_constant=lambda _: reject_constant()
    )
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Неизвестные или отсутствующие поля")
    if type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("Неверная версия схемы")
    return value


def reject_constant() -> None:
    raise ValueError("Недопустимая константа JSON")


def hex_bytes(value: object, length: int = 32) -> list[int]:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{%d}" % (length * 2), value) is None
    ):
        raise ValueError("Требуется точный lowercase hex")
    decoded = bytes.fromhex(value)
    if not any(decoded):
        raise ValueError("Нулевой идентификатор запрещён")
    return list(decoded)


def produce(
    worker: Path, source: Path, receipt: Path, provenance: Path
) -> tuple[dict, dict]:
    """Связь source→ELF утверждается только доверенной внешней квитанцией."""
    build = read_data(receipt, {"schema", "worker_sha256", "source_archive_sha256"})
    pins = read_data(
        provenance,
        {
            "schema",
            "policy_id",
            "policy_sha256",
            "kernel_release",
            "kernel_machine",
            "kernel_abi",
            "kernel_build_id",
        },
    )
    for key in ("worker_sha256", "source_archive_sha256"):
        hex_bytes(build[key])
    hex_bytes(pins["policy_sha256"])
    kernel_id = hex_bytes(pins["kernel_build_id"], 20)
    release = pins["kernel_release"]
    if (
        pins["policy_id"] != POLICY
        or pins["kernel_machine"] != "x86_64"
        or pins["kernel_abi"] != ABI
        or not isinstance(release, str)
        or re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", release) is None
    ):
        raise ValueError("Несовместимый policy/kernel tuple")
    actual_worker, _ = read_artifact(worker, MAX_ELF, elf=True)
    actual_source, _ = read_artifact(source, MAX_SOURCE)
    if (
        build["worker_sha256"] != actual_worker
        or build["source_archive_sha256"] != actual_source
    ):
        raise ValueError("Артефакты не соответствуют доверенной квитанции")
    manifest = dict(pins)
    manifest["kernel_build_id"] = kernel_id
    manifest["policy_sha256"] = hex_bytes(pins["policy_sha256"])
    manifest["worker_sha256"] = hex_bytes(actual_worker)
    manifest["source_archive_sha256"] = hex_bytes(actual_source)
    report = {
        "status": "UNREGISTERED",
        "admission": "NOT_ADMISSION",
        "source_elf_binding": "asserted_by_caller_trusted_build_receipt",
        "worker_sha256": actual_worker,
        "source_archive_sha256": actual_source,
        "frozen_control_policy_sha256": FROZEN_CONTROL,
        "warning": "Хеши не доказывают компиляцию; профиль не одобрен и не установлен",
    }
    return manifest, report


def encode(value: dict) -> bytes:
    raw = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    if len(raw) > MAX_METADATA:
        raise ValueError("Выход превышает предел metadata")
    return raw


def emit(output: Path, manifest: dict, report: dict) -> None:
    """Только новый каталог внутри текущего workspace; каждый файл публикуется атомарно."""
    payloads = [("deployment.json", encode(manifest)), ("report.json", encode(report))]
    absolute = Path(os.path.abspath(output))
    workspace = Path.cwd().resolve()
    if not absolute.is_relative_to(workspace) or absolute == workspace:
        raise ValueError("Выход должен быть новым каталогом внутри workspace")
    forbidden = (
        "/usr",
        "/etc",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/var/lib",
        "/var/cache",
    )
    if any(absolute.is_relative_to(Path(prefix)) for prefix in forbidden):
        raise ValueError("Системный путь выхода запрещён")
    parent = open_regular_directory(absolute.parent)
    try:
        if os.fstat(parent).st_uid != os.geteuid():
            raise ValueError("Родитель выхода не принадлежит текущему пользователю")
        os.mkdir(absolute.name, 0o700, dir_fd=parent)
        directory = os.open(
            absolute.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            for name, raw in payloads:
                # Каталог эксклюзивный, недоступен другим uid; link не перезаписывает имя.
                temporary = "." + name + ".tmp"
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
                os.link(
                    temporary,
                    name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
            os.fsync(parent)
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def open_regular_directory(path: Path) -> int:
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "source", "receipt", "provenance", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest, report = produce(
            args.worker, args.source, args.receipt, args.provenance
        )
        emit(args.output, manifest, report)
    except (OSError, ValueError, RecursionError) as error:
        parser.exit(2, f"Кандидат отклонён: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
