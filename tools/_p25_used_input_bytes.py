"""Полные actual-used Qt SDK bytes: post-capture input, без legal/admission gate."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from _p25_attribution_join import RECORD_FIELDS, _absolute, _document, _files
from _p25_capture_producer import _directory
from p25_capture_build_closure import (
    MAX_FILES,
    MAX_METADATA,
    CaptureError,
    identity,
    ids,
    object_fields,
    relative,
    require,
    sequence,
    sha,
)

# Только trusted code profile; JSON и caller не могут расширять roots.
SDK_ROOTS = (Path("/usr/include/qt6"),)
MAX_INPUT = 16 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
OBS_FIELDS = set("schema records qt input_origins config config_sha256".split())
ROW_FIELDS = set(
    "schema config_sha256 argv original_argv cwd compiler exit depfile unit stdout_sha256 stderr_sha256 compiler_id raw_depfile_sha256 normalized_depfile".split()
)


def _object(value: object, fields: str) -> dict:
    keys = set(fields.split())
    return object_fields(value, keys, keys)


def _schema(value: dict) -> None:
    require(type(value["schema"]) is int and value["schema"] == 1, "Unknown schema")


def _argv(value: object) -> tuple[str, ...]:
    values = sequence(value)
    require(
        bool(values)
        and all(
            isinstance(v, str) and 0 < len(v) <= 4096 and "\0" not in v for v in values
        ),
        "Неверный argv",
    )
    return tuple(values)


def _tool(value: object) -> None:
    row = _object(value, "path sha256")
    _absolute(row["path"])
    sha(row["sha256"])


def _inputs(
    record_raw: bytes, record_pin: str, observed_raw: bytes, observed_pin: str
) -> tuple[dict, dict, set[str]]:
    for raw, pin, cap in (
        (record_raw, record_pin, MAX_METADATA),
        (observed_raw, observed_pin, 8 * MAX_METADATA),
    ):
        require(
            isinstance(raw, bytes)
            and len(raw) <= cap
            and hashlib.sha256(raw).hexdigest() == sha(pin),
            "Input pin/cap mismatch",
        )
    record = _document(record_raw, MAX_METADATA, RECORD_FIELDS, RECORD_FIELDS)
    source = _object(record["source"], "commit tree archive_sha256 tracked_inputs")
    for key in ("commit", "tree"):
        require(
            isinstance(source[key], str)
            and len(source[key]) == 40
            and all(c in "0123456789abcdef" for c in source[key]),
            "Git identity",
        )
    sha(source["archive_sha256"])
    ids(source["tracked_inputs"])
    profile = _object(record["profile"], "target commands features")
    require(isinstance(profile["target"], str), "Target type")
    for command in sequence(profile["commands"]):
        _argv(command)
    require(
        all(isinstance(v, str) for v in sequence(profile["features"])), "Features type"
    )
    files = _files(record["files"])
    ids(record["elfs"])
    for row in files.values():
        if "source_ref" in row:
            identity(row["source_ref"])
    # Этот input не принимает generator/primary assertions: они остаются отдельным join.
    require(
        record["generated"] == [] and record["primary_refs"] == [],
        "Unsupported provenance assertions",
    )
    if record["qt_version"] is not None:
        identity(record["qt_version"])
    units = set()
    for unit in sequence(record["units"]):
        _object(unit, "file depfile argv")
        require(
            identity(unit["file"]) in files and identity(unit["depfile"]) in files,
            "Unknown unit reference",
        )
        key = (unit["file"], _argv(unit["argv"]))
        require(key not in units, "Duplicate unit")
        units.add(key)
    observed = _document(
        observed_raw, 8 * MAX_METADATA, OBS_FIELDS | {"aliases"}, OBS_FIELDS, (1, 2)
    )
    from _p25_final_profile import validate_observed_extensions

    validate_observed_extensions(observed, record["files"])
    config = _object(observed["config"], "schema source build sdk")
    _schema(config)
    for key in ("source", "build", "sdk"):
        _absolute(config[key])
    require(config["sdk"] == "/usr", "Unknown SDK profile")
    sha(observed["config_sha256"])
    qt = _object(
        observed["qt"], "schema query_argv version exit tool stdout stderr_sha256"
    )
    _schema(qt)
    _argv(qt["query_argv"])
    _tool(qt["tool"])
    require(
        type(qt["exit"]) is int
        and qt["exit"] == 0
        and isinstance(qt["version"], str)
        and isinstance(qt["stdout"], str),
        "Invalid query record",
    )
    sha(qt["stderr_sha256"])
    origins = observed["input_origins"]
    require(
        isinstance(origins, dict) and len(origins) <= MAX_FILES, "Origin map cap/type"
    )
    for origin, local in origins.items():
        _absolute(origin)
        relative(local)
    used: set[str] = set()
    seen = set()
    count = 0
    from _p25_final_profile import validate_purpose

    for row in sequence(observed["records"]):
        require(isinstance(row, dict), "Observed record type")
        fields = ROW_FIELDS | (
            {"purpose", "probe"} if row.get("schema") == 2 else set()
        )
        object_fields(
            row, fields, fields - {"normalized_depfile", "raw_depfile_sha256"}
        )
        validate_purpose(row, Path(config["build"]))
        _tool(row["compiler"])
        _argv(row["original_argv"])
        argv = _argv(row["argv"])
        _absolute(row["cwd"])
        identity(row["compiler_id"])
        for key in ("config_sha256", "stdout_sha256", "stderr_sha256"):
            sha(row[key])
        require(
            row["config_sha256"] == observed["config_sha256"]
            and type(row["exit"]) is int,
            "Unsuccessful/unbound observation",
        )
        if row["unit"] is None:
            require(
                row["depfile"] is None
                and "normalized_depfile" not in row
                and "raw_depfile_sha256" not in row,
                "Probe dependency assertion",
            )
            continue
        _absolute(row["unit"])
        relative(row["depfile"])
        sha(row["raw_depfile_sha256"])
        dep = _object(row["normalized_depfile"], "schema unit dependencies")
        _schema(dep)
        deps = ids(dep["dependencies"])
        key = (identity(dep["unit"]), argv)
        require(
            key in units and key not in seen and dep["unit"] in deps,
            "Dependency/unit binding",
        )
        seen.add(key)
        require(all(v in files for v in deps), "Unknown dependency ID")
        count += len(deps)
        require(count <= 10000, "Dependency row cap")
        used.update(deps)
    require(seen == units, "Missing observed units")
    return files, origins, used


def _signature(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _consume(path: Path, expected: str, output_fd: int | None, limit: int) -> bytes:
    """NOFOLLOW каждого компонента, затем повторный pathname walk после чтения."""
    parent = _directory(path.parent)
    try:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "Input type/size cap",
            )
            digest = hashlib.sha256()
            size = 0
            chunks = []
            while chunk := os.read(fd, 65536):
                size += len(chunk)
                require(size <= limit, "Input byte cap")
                digest.update(chunk)
                if output_fd is None:
                    chunks.append(chunk)
                else:
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output_fd, view)
                        require(written > 0, "Short write")
                        view = view[written:]
            require(
                _signature(before) == _signature(os.fstat(fd))
                and size == before.st_size
                and digest.hexdigest() == expected,
                "Changed input/hash mismatch",
            )
            current = _directory(path.parent)
            try:
                require(
                    (os.fstat(parent).st_dev, os.fstat(parent).st_ino)
                    == (os.fstat(current).st_dev, os.fstat(current).st_ino),
                    "Changed parent identity",
                )
                require(
                    _signature(before)
                    == _signature(
                        os.stat(path.name, dir_fd=current, follow_symlinks=False)
                    ),
                    "Changed pathname identity",
                )
            finally:
                os.close(current)
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def retain_used_input_bytes(
    record: bytes,
    record_sha256: str,
    observed: bytes,
    observed_sha256: str,
    output: Path,
) -> dict:
    """Новый exclusive workspace output. Ошибка оставляет только незавершённый каталог.

    Pins обязан независимо проверить caller. SDK roots фиксированы trusted profile;
    generated bytes здесь не читаются. Успех retention не означает source closure.
    """
    try:
        files, origins, used = _inputs(record, record_sha256, observed, observed_sha256)
        by_local: dict[str, list[str]] = {}
        for origin, local in origins.items():
            by_local.setdefault(local, []).append(origin)
        selected = []
        missing = []
        for key in files:
            if key not in used:
                continue
            row = files[key]
            if row["kind"] == "generated":
                missing.append("generated-retained-bytes:" + key)
            if row["kind"] not in ("header", "sdk-unit"):
                continue
            candidates = by_local.get(row["path"], [])
            if not candidates or "sha256" not in row:
                missing.append("origin-or-sha256:" + key)
                continue
            for origin in candidates:
                path = Path(origin)
                require(
                    any(
                        path != root and path.is_relative_to(root) for root in SDK_ROOTS
                    ),
                    "Origin outside trusted Qt SDK roots",
                )
                selected.append((key, path, sha(row["sha256"])))
        require(len(selected) <= MAX_FILES, "Input count cap")
        require(
            output.is_absolute() and output.name not in ("", ".", ".."),
            "Invalid output",
        )
        parent = _directory(output.parent)
        try:
            os.mkdir(output.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        directory = _directory(output)
        try:
            total = 0
            objects: dict[str, int] = {}
            retained = []
            for key, path, checksum in selected:
                # Даже dedup origin проверяется независимо; total считает прочитанные bytes.
                fd = os.open(
                    checksum if checksum not in objects else ".verify",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    _consume(path, checksum, fd, min(MAX_INPUT, MAX_BYTES - total))
                    size = os.fstat(fd).st_size
                    total += size
                    os.fsync(fd)
                finally:
                    os.close(fd)
                    if checksum in objects:
                        os.unlink(".verify", dir_fd=directory)
                objects[checksum] = size
                retained.append(
                    {
                        "id": key,
                        "origin": str(path),
                        "sha256": checksum,
                        "bytes": size,
                        "object": checksum,
                    }
                )
            if not retained:
                missing.append("actual-used-sdk-bytes")
            result = {
                "schema": 1,
                "kind": "USED_INPUT_BYTES",
                "status": "MISSING" if missing else "RETAINED",
                "missing": missing,
                "record_sha256": record_sha256,
                "observed_sha256": observed_sha256,
                "inputs": retained,
                "read_bytes": total,
                "legal_status": "NOTPROVEN",
                "full_source_closure": "OPEN",
                "generator_identity": "MISSING",
                "final_linux_acceptance": False,
                "production_admission_gate": False,
            }
            raw = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
            require(len(raw) <= 8 * MAX_METADATA, "Output manifest cap")
            fd = os.open(
                "manifest.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            except BaseException:
                os.unlink("manifest.json", dir_fd=directory)
                raise
            return result
        finally:
            os.close(directory)
    except CaptureError:
        raise
    except (OSError, KeyError, TypeError, ValueError, RecursionError) as error:
        raise CaptureError("Used-input retention rejected: " + str(error)) from error
