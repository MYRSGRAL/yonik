"""Retained Cargo registry proof: внешне доверенная проекция, не attestation."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tarfile
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from n5_capture_receipts import RetainedReader

from n5_build_manifest import MAX_SOURCE, open_regular_directory
from p25_capture_build_closure import (
    MAX_METADATA,
    parse,
    relative,
    require,
    sequence,
    sha,
)

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_PACKAGES = 128
MAX_ARCHIVES_TOTAL = 256 * 1024 * 1024

SCHEMA = "P25_CARGO_REGISTRY_PROOF_V1"
INPUTS = (
    "frozen.json",
    "build-capture-record.json",
    "build-capture-report.json",
    "build-cxx-observed.json",
)


def exact(value: object, keys: set[str]) -> dict:
    require(isinstance(value, dict) and set(value) == keys, "Registry proof fields")
    return value


def lock_bytes(reader: RetainedReader, archive_pin: str) -> bytes:
    """Только exact Cargo.lock из pinned raw source.tar; без extracted source."""
    from _p25_final_profile import _registry_tar

    digest, raw = reader.read_file("source.tar", MAX_SOURCE)
    require(digest == sha(archive_pin), "Registry source archive pin mismatch")
    lock = None
    names = set()
    with _registry_tar(raw, gzip_encoded=False) as archive:
        for index, member in enumerate(archive):
            require(index < 100000, "Registry source member cap")
            require(
                member.isdir() or not member.name.endswith("/"),
                "Registry source member path/type",
            )
            name = relative(member.name.rstrip("/"))
            require(name not in names, "Registry source duplicate member")
            names.add(name)
            if name != "src/Cargo.lock":
                continue
            require(
                member.isfile() and 0 <= member.size <= MAX_METADATA,
                "Registry Cargo.lock type/cap",
            )
            stream = archive.extractfile(member)
            require(stream is not None, "Registry Cargo.lock missing bytes")
            with stream:
                lock = stream.read(member.size + 1)
            require(len(lock) == member.size, "Registry Cargo.lock size")
    require(lock is not None, "MISSING: frozen source Cargo.lock")
    return lock


def inputs(
    reader: RetainedReader, pins: dict[str, str], commit: str
) -> tuple[dict, dict, dict, dict, bytes]:
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "Registry source commit")
    values = []
    for name in INPUTS:
        digest, raw = reader.read_file(
            name,
            32 * MAX_METADATA if name.endswith("report.json") else 8 * MAX_METADATA,
        )
        require(digest == sha(pins[name]), "Registry independent input pin mismatch")
        values.append(parse(raw))
    frozen, record, report, observed = values
    require(
        all(isinstance(value, dict) for value in values), "Registry input metadata type"
    )
    require(
        isinstance(observed["input_origins"], dict)
        and len(observed["input_origins"]) <= 4096
        and all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in observed["input_origins"].items()
        ),
        "Registry origins schema/cap",
    )
    from _p25_final_profile import validate_observed_extensions, validate_purpose

    validate_observed_extensions(observed, record["files"])
    for row in sequence(observed["records"]):
        require(isinstance(row, dict), "Registry observed record type")
        validate_purpose(row, Path(observed["config"]["build"]))
        argv = sequence(row["original_argv"])
        require(
            all(isinstance(arg, str) and 0 < len(arg) <= 4096 for arg in argv),
            "Registry observed argv type/cap",
        )
        require(
            row["unit"] is None or isinstance(row["unit"], str),
            "Registry observed unit type",
        )
    for metadata in (record, report):
        for row in sequence(metadata["files"]):
            require(isinstance(row, dict), "Registry file metadata type")
            require(
                all(
                    isinstance(row[key], str)
                    for key in ("id", "root", "path", "kind", "sha256")
                ),
                "Registry file identity type",
            )
    require(
        frozen["source"]["commit"] == commit
        and frozen["archive_sha256"] == pins["source.tar"],
        "Registry frozen source mismatch",
    )
    require(
        record["source"]["commit"] == commit
        and record["source"]["archive_sha256"] == pins["source.tar"]
        and report["source"] == record["source"],
        "Registry captured source mismatch",
    )
    require(
        observed["config"]["source"] == report["roots"]["source"]
        and observed["config"]["build"] == report["roots"]["build"],
        "Registry captured roots mismatch",
    )
    lock = lock_bytes(reader, pins["source.tar"])
    return frozen, record, report, observed, lock


def selected(observed: dict, lock: bytes) -> dict[str, dict]:
    from _p25_final_profile import PROFILE

    packages = tomllib.loads(lock.decode())["package"]
    require(
        isinstance(packages, list) and len(packages) <= 4096,
        "Registry lock package cap",
    )
    locked: dict[str, list[dict]] = {}
    for package in packages:
        require(isinstance(package, dict), "Registry lock package type")
        if (
            package.get("source")
            == "registry+https://github.com/rust-lang/crates.io-index"
        ):
            locked.setdefault(
                f"{package.get('name')}-{package.get('version')}", []
            ).append(package)
    result = {}
    roots = [Path(observed["config"][key]) for key in ("source", "build")]
    base = Path(PROFILE["registry_source_root"]) / "index.crates.io-1949cf8c6b5b557f"
    contexts = set()
    for row in observed["records"]:
        cwd = row["cwd"]
        require(
            isinstance(cwd, str)
            and Path(cwd).is_absolute()
            and ".." not in Path(cwd).parts,
            "Registry cwd path",
        )
        if not any(Path(cwd).is_relative_to(root) for root in roots):
            contexts.add(cwd)
    registry = Path(PROFILE["registry_source_root"])
    for origin in observed["input_origins"]:
        require(isinstance(origin, str), "Registry origin type")
        path = Path(origin)
        if not path.is_relative_to(registry):
            continue
        require(
            path.is_absolute() and ".." not in path.parts and str(path) == origin,
            "Registry origin path",
        )
        parts = path.relative_to(registry).parts
        require(len(parts) >= 3, "Registry origin package member")
        contexts.add(str(registry / parts[0] / parts[1]))
    for cwd in sorted(contexts):
        path = Path(cwd)
        if any(path.is_relative_to(root) for root in roots):
            continue
        require(path.parent == base and str(path) == cwd, "Registry exact cwd required")
        if cwd in result:
            continue
        matches = locked.get(path.name, [])
        require(len(matches) == 1, "Registry cwd not selected by frozen lock")
        package = matches[0]
        sha(package["checksum"])
        result[cwd] = package
        require(len(result) <= MAX_PACKAGES, "Registry selected package cap")
    return result


def unit_bindings(cwd: str, record: dict, report: dict, observed: dict) -> list[dict]:
    rows = {row["id"]: row for row in record["files"]}
    verified = {row["id"]: row for row in report["files"]}
    require(
        len(rows) == len(record["files"]) and len(verified) == len(report["files"]),
        "Registry duplicate input ID",
    )
    sdk_paths: dict[str, list[dict]] = {}
    compiles: dict[str, list[dict]] = {}
    for row in rows.values():
        if row["root"] == "sdk":
            sdk_paths.setdefault(row["path"], []).append(row)
    for item in observed["records"]:
        if item["unit"] is not None:
            compiles.setdefault(item["unit"], []).append(item)
    roots = [Path(observed["config"][key]) for key in ("source", "build")]
    for item in observed["records"]:
        if item["cwd"] != cwd:
            continue
        for arg in item["original_argv"]:
            if not arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++")):
                continue
            path = Path(arg) if Path(arg).is_absolute() else Path(cwd) / arg
            require(".." not in path.parts, "Registry observed unit traversal")
            if any(path.is_relative_to(root) for root in roots):
                continue
            require(
                path.is_relative_to(Path(cwd)), "Registry observed unit/cwd mismatch"
            )
            if item["unit"] is None:
                continue
            require(
                str(path) in observed["input_origins"],
                "MISSING: registry observed unit origin",
            )
            staged = observed["input_origins"][str(path)]
            matches = sdk_paths.get(staged, [])
            require(
                len(matches) == 1
                and matches[0]["kind"] == "sdk-unit"
                and item["unit"] == str(path),
                "Registry observed compile unit mismatch",
            )
    result = []
    for origin, staged in observed["input_origins"].items():
        path = Path(origin)
        if not path.is_relative_to(Path(cwd)):
            continue
        require(
            ".." not in path.parts and path.is_absolute() and str(path) == origin,
            "Registry unit origin path",
        )
        matches = sdk_paths.get(staged, [])
        require(
            len(matches) == 1 and staged == hashlib.sha256(origin.encode()).hexdigest(),
            "Registry staged origin mismatch",
        )
        row = matches[0]
        require(row["kind"] in ("sdk-unit", "header"), "Registry input kind")
        require(
            verified.get(row["id"]) == dict(row, verified=True),
            "Registry report unit mismatch",
        )
        actual_compiles = compiles.get(origin, [])
        if row["kind"] == "sdk-unit":
            require(bool(actual_compiles), "Registry unit not observed")
            for item in actual_compiles:
                require(
                    item["cwd"] == cwd
                    or any(Path(item["cwd"]).is_relative_to(root) for root in roots),
                    "Registry unit/cwd mismatch",
                )
        result.append(
            {
                "kind": row["kind"],
                "file_id": row["id"],
                "member_path": relative(path.relative_to(Path(cwd)).as_posix()),
                "sha256": sha(row["sha256"]),
            }
        )
    return sorted(result, key=lambda row: row["file_id"])


def probe_members(cwd: str, observed: dict) -> set[str]:
    members = set()
    for item in observed["records"]:
        if item["cwd"] != cwd or item["unit"] is not None:
            continue
        for arg in item["original_argv"]:
            if arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++")):
                path = Path(arg) if Path(arg).is_absolute() else Path(cwd) / arg
                if path.is_relative_to(Path(cwd)):
                    members.add(relative(path.relative_to(Path(cwd)).as_posix()))
    return members


def archive_units(
    raw: bytes,
    package: str,
    units: list[dict],
    context_members: set[str],
    *,
    payload_budget: int | None = None,
) -> list[dict]:
    """Hash exact regular members после shared bounded archive validation."""
    from _p25_final_profile import _registry_tar

    result = []
    remaining = MAX_ARCHIVES_TOTAL if payload_budget is None else payload_budget
    require(type(remaining) is int and remaining >= 0, "Registry payload budget")
    expected = {unit["member_path"]: unit for unit in units}
    require(len(expected) == len(units), "Registry duplicate selected member")
    seen = set()
    names = set()
    require(0 < len(raw) <= MAX_ARCHIVE, "Registry compressed archive cap")
    expanded = 0
    try:
        with _registry_tar(raw) as archive:
            for member in archive:
                expanded += member.size
                require(
                    expanded <= MAX_ARCHIVE and len(names) < 4096,
                    "Registry expanded archive cap",
                )
                require(
                    member.isdir() or not member.name.endswith("/"),
                    "Registry member path/type",
                )
                name = member.name.rstrip("/")
                relative(name)
                require(
                    name.split("/")[0] == package, "Registry archive package prefix"
                )
                require(name not in names, "Registry duplicate archive member")
                names.add(name)
                if member.isdir():
                    require(member.size == 0, "Registry directory payload")
                    continue
                require(
                    member.isfile() and 0 <= member.size <= MAX_ARCHIVE,
                    "Registry archive member type/cap",
                )
                path = relative("/".join(name.split("/")[1:]))
                require(path not in seen, "Registry duplicate archive member")
                seen.add(path)
                if path not in expected:
                    continue
                require(member.size <= remaining, "Registry payload aggregate cap")
                remaining -= member.size
                stream = archive.extractfile(member)
                require(stream is not None, "Registry archive missing selected bytes")
                with stream:
                    content = stream.read(member.size + 1)
                unit = expected[path]
                require(
                    len(content) == member.size
                    and hashlib.sha256(content).hexdigest() == unit["sha256"],
                    "Registry member/staged SHA mismatch",
                )
                result.append({**unit, "size": len(content), "bytes": content})
    except tarfile.TarError as error:
        raise ValueError("Registry archive invalid") from error
    require(context_members <= seen, "MISSING: registry probe member")
    require(
        {unit["member_path"] for unit in result} == set(expected),
        "MISSING: selected registry archive member",
    )
    return sorted(result, key=lambda row: row["file_id"])


def proof_rows(inputs: list[dict], kind: str) -> list[dict]:
    return [
        {key: value for key, value in item.items() if key not in ("bytes", "kind")}
        for item in inputs
        if item["kind"] == kind
    ]


def validate(
    reader: RetainedReader,
    proof_path: str,
    proof_pin: str,
    pins: dict[str, str],
    commit: str,
) -> tuple[set[str], dict[tuple[str, str], bytes]]:
    relative(proof_path)
    digest, raw = reader.read_file(proof_path, 8 * MAX_METADATA)
    require(digest == sha(proof_pin), "Registry proof independent pin mismatch")
    proof = exact(
        parse(raw),
        {
            "schema",
            "source_commit",
            "source_archive_sha256",
            "cargo_lock_sha256",
            "input_sha256",
            "packages",
        },
    )
    _, record, report, observed, lock = inputs(reader, pins, commit)
    require(
        proof["schema"] == SCHEMA
        and proof["source_commit"] == commit
        and proof["source_archive_sha256"] == pins["source.tar"]
        and proof["cargo_lock_sha256"] == hashlib.sha256(lock).hexdigest()
        and proof["input_sha256"] == {name: pins[name] for name in INPUTS},
        "Registry proof source/input binding",
    )
    expected = selected(observed, lock)
    require(
        isinstance(proof["packages"], list) and len(proof["packages"]) == len(expected),
        "Registry proof package count",
    )
    seen = set()
    payloads = {}
    archives = {}
    payload_bytes = 0
    for item in proof["packages"]:
        exact(
            item,
            {
                "cwd",
                "name",
                "version",
                "checksum",
                "archive_path",
                "archive_size",
                "archive_sha256",
                "units",
                "headers",
            },
        )
        cwd = item["cwd"]
        require(
            isinstance(cwd, str) and cwd in expected and cwd not in seen,
            "Registry proof package mismatch",
        )
        seen.add(cwd)
        package = expected[cwd]
        require(
            all(item[key] == package[key] for key in ("name", "version", "checksum")),
            "Registry proof lock mismatch",
        )
        checksum = sha(item["archive_sha256"])
        require(
            checksum == package["checksum"]
            and item["archive_path"] == "registry-archives/" + checksum + ".crate",
            "Registry archive identity",
        )
        require(
            type(item["archive_size"]) is int
            and 0 < item["archive_size"] <= MAX_ARCHIVE,
            "Registry archive size",
        )
        if checksum not in archives:
            actual, archive = reader.read_file(item["archive_path"], MAX_ARCHIVE)
            require(actual == checksum, "Registry retained archive hash")
            require(
                sum(map(len, archives.values())) + len(archive) + len(raw)
                <= MAX_ARCHIVES_TOTAL,
                "Registry retained aggregate cap",
            )
            archives[checksum] = archive
        archive = archives[checksum]
        require(
            len(archive) == item["archive_size"],
            "Registry retained archive size mismatch",
        )
        for category in ("units", "headers"):
            require(
                isinstance(item[category], list) and len(item[category]) <= 4096,
                "Registry proof input cap",
            )
            for unit in item[category]:
                exact(unit, {"file_id", "member_path", "size", "sha256"})
                require(
                    type(unit["size"]) is int and 0 <= unit["size"] <= MAX_ARCHIVE,
                    "Registry proof input size",
                )
        units = archive_units(
            archive,
            Path(cwd).name,
            unit_bindings(cwd, record, report, observed),
            probe_members(cwd, observed),
            payload_budget=MAX_ARCHIVES_TOTAL - payload_bytes,
        )
        payload_bytes += sum(len(unit["bytes"]) for unit in units)
        for category, kind in (("units", "sdk-unit"), ("headers", "header")):
            require(
                item[category] == proof_rows(units, kind),
                "Registry proof input mismatch",
            )
        for unit in units:
            origin = cwd + "/" + unit["member_path"]
            payloads["sdk", observed["input_origins"][origin]] = unit["bytes"]
    require(seen == set(expected), "MISSING: registry cwd proof")
    return seen, payloads


def produce(retained: Path, pins: dict[str, str], commit: str) -> tuple[dict, str]:
    """После capture читает только точные selected cached archives, пишет sidecar один раз."""
    from _p25_final_profile import PROFILE
    from n5_capture_receipts import RetainedReader, retained_json

    reader = RetainedReader(retained)
    _, record, report, observed, lock = inputs(reader, pins, commit)
    roots = [Path(observed["config"][key]) for key in ("source", "build")]
    require(
        any(
            not any(Path(row["cwd"]).is_relative_to(root) for root in roots)
            for row in observed["records"]
        ),
        "Registry proof без registry cwd",
    )
    packages = selected(observed, lock)
    result = {
        "schema": SCHEMA,
        "source_commit": commit,
        "source_archive_sha256": pins["source.tar"],
        "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "input_sha256": {name: pins[name] for name in INPUTS},
        "packages": [],
    }
    archives = {}
    payload_bytes = 0
    cache = RetainedReader(Path(PROFILE["registry_source_root"]).parent / "cache")
    for cwd, package in sorted(packages.items()):
        checksum = package["checksum"]
        local = Path(cwd).parent.name + "/" + Path(cwd).name + ".crate"
        if checksum not in archives:
            digest, archive = cache.read_file(local, MAX_ARCHIVE)
            require(digest == checksum, "Registry cache checksum mismatch")
            require(
                sum(map(len, archives.values())) + len(archive) <= MAX_ARCHIVES_TOTAL,
                "Registry retained aggregate cap",
            )
            archives[checksum] = archive
        archive = archives[checksum]
        units = archive_units(
            archive,
            Path(cwd).name,
            unit_bindings(cwd, record, report, observed),
            probe_members(cwd, observed),
            payload_budget=MAX_ARCHIVES_TOTAL - payload_bytes,
        )
        payload_bytes += sum(len(unit["bytes"]) for unit in units)
        result["packages"].append(
            {
                "cwd": cwd,
                **{key: package[key] for key in ("name", "version", "checksum")},
                "archive_path": "registry-archives/" + checksum + ".crate",
                "archive_size": len(archive),
                "archive_sha256": checksum,
                "units": proof_rows(units, "sdk-unit"),
                "headers": proof_rows(units, "header"),
            }
        )
    for observed_reader in (reader, cache):
        for name, digest in list(observed_reader.seen.items()):
            actual, _ = observed_reader.read_file(
                name, MAX_SOURCE if name == "source.tar" else MAX_ARCHIVE, False
            )
            require(actual == digest, "Registry producer input changed after join")
    proof_raw = retained_json(result)
    require(len(proof_raw) <= 8 * MAX_METADATA, "Registry proof byte cap")
    require(
        sum(map(len, archives.values())) + len(proof_raw) <= MAX_ARCHIVES_TOTAL,
        "Registry retained aggregate cap",
    )
    directory = open_regular_directory(retained)
    try:
        os.mkdir("registry-archives", 0o700, dir_fd=directory)
    finally:
        os.close(directory)
    for name, raw in {
        **{
            "registry-archives/" + key + ".crate": value
            for key, value in archives.items()
        },
        "registry-proof.json": proof_raw,
    }.items():
        parent = open_regular_directory((retained / name).parent)
        try:
            fd = os.open(
                Path(name).name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
    return result, hashlib.sha256(proof_raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    for name in (*INPUTS, "source.tar"):
        parser.add_argument(
            "--" + name.replace(".", "-") + "-sha256", dest=name, required=True
        )
    args = vars(parser.parse_args())
    try:
        _, pin = produce(
            args["retained"],
            {name: args[name] for name in (*INPUTS, "source.tar")},
            args["source_commit"],
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        parser.exit(2, f"Registry proof отклонён: {error}\n")
    sys.stdout.write("registry-proof.json sha256=" + pin + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
