#!/usr/bin/env python3
"""Проекция внешне доверенного Rust capture; не compile attestation/admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from n5_build_manifest import (
    MAX_ELF,
    MAX_SOURCE,
    open_regular,
    open_regular_directory,
    read_artifact,
    stamp,
)
from p25_capture_build_closure import (
    MAX_METADATA,
    _capture,
    identity,
    ids,
    object_fields,
    parse,
    relative,
    require,
    sequence,
    sha,
)
from release_controller import CONTROLLED_ENV, RECIPE, RUST, SLOT, elf_header

METADATA = (
    "rust-captured-only.json",
    "build-capture-manifest.json",
    "build-capture-record.json",
    "build-capture-report.json",
    "frozen.json",
)
ROLES = dict(zip(("desktop", "helper", "worker"), RUST, strict=True))
PRODUCER_MISSING = [
    "cxx:invocations",
    "cxx:normalized-depfiles",
    "generated:paths-and-generation-records",
    "qt:observed-query-and-tool",
    "qt:header-source-primary-join",
]


def encode(value: dict) -> bytes:
    """Детерминированные байты receipt/report."""
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        + "\n"
    ).encode()
    require(len(raw) <= 32 * MAX_METADATA, "Выход превышает cap")
    return raw


class RetainedReader:
    """Адаптер конечного Rust whitelist для существующего capture validator."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.total = 0
        self.virtual: dict[tuple[str, str], bytes] = {}
        self.enriched_paths: set[tuple[str, str]] = set()
        self.seen: dict[str, str] = {}
        self.identities: dict[str, tuple[int, ...]] = {}

    def _consume(
        self, root: str, path: str, limit: int, content: bool
    ) -> tuple[bytes, str]:
        if (root, path) in self.virtual:
            raw = self.virtual[root, path]
            require(len(raw) <= limit, "Virtual capture cap")
            self.total += len(raw)
            require(self.total <= 2 * 1024**3, "Total capture cap")
            return (raw if content else b""), hashlib.sha256(raw).hexdigest()
        if (root, path) in self.enriched_paths and not (
            root == "build" and path in {"release/" + name for name in RUST}
        ):
            raise FileNotFoundError("Captured input bytes no longer retained")
        require(root == "build", "Rust-only capture не содержит иных roots")
        names = {"capture-record.json": "build-capture-record.json"}
        names.update({"release/" + name: name for name in RUST})
        require(path in names, "Путь вне retained whitelist")
        digest, raw = self.read_file(names[path], limit, content)
        return raw, digest

    def read_file(
        self, name: str, limit: int, content: bool = True
    ) -> tuple[str, bytes]:
        fd = open_regular(self.root / name)
        try:
            before = stamp(os.fstat(fd))
        finally:
            os.close(fd)
        require(
            name not in self.identities or self.identities[name] == before,
            "Путь подменён между чтениями",
        )
        digest, raw = read_artifact(self.root / name, limit, collect=content)
        fd = open_regular(self.root / name)
        try:
            require(stamp(os.fstat(fd)) == before, "Путь изменился при join")
        finally:
            os.close(fd)
        self.identities[name] = before
        require(name not in self.seen or self.seen[name] == digest, "Вход изменился")
        self.seen[name] = digest
        self.total += before[2]
        require(self.total <= 2 * 1024**3, "Общий cap чтения превышен")
        return digest, raw

    def read(self, root: str, path: str, limit: int) -> bytes:
        return self._consume(root, path, limit, True)[0]


def exact(value: object, fields: set[str]) -> dict:
    return object_fields(value, fields, fields)


def same(left: object, right: object) -> bool:
    """JSON equality без Python-эквивалентности true == 1."""
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def retained_json(value: dict) -> bytes:
    """Точные байты JSON, которые пишет capture producer (_write)."""
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def final_capture(
    reader: RetainedReader,
    frozen: dict,
    manifest: dict,
    record: dict,
    report: dict,
    observed_pin: str,
    registry_cwds: set[str] | None = None,
) -> dict:
    """Узкий offline join enriched evidence; никаких build-time методов enrich/prepare."""
    from _p25_final_profile import (
        PROFILE,
        compile_arguments,
        validate_aliases,
        validate_purpose,
    )

    profile = exact(frozen["final_profile"], {"spec", "tooling_sha256", "sha256"})
    require(
        json.dumps(profile["spec"], sort_keys=True)
        == json.dumps(PROFILE, sort_keys=True),
        "Final profile spec mismatch",
    )
    tooling = exact(
        profile["tooling_sha256"],
        {
            "_p25_final_profile.py",
            "p25_cxx_capture_wrapper.py",
            "_p25_capture_producer.py",
            "p25_capture_build_closure.py",
        },
    )
    for pin in tooling.values():
        sha(pin)
    body = {"spec": profile["spec"], "tooling_sha256": tooling}
    require(
        profile["sha256"]
        == hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
        "Final profile digest mismatch",
    )
    require(same(manifest["final_profile"], profile), "Manifest final profile conflict")
    digest, raw = reader.read_file(
        "build-cxx-observed.json", PROFILE["observed_metadata_cap"]
    )
    positive = exact(
        manifest["positive_metadata"],
        {
            "producer_missing",
            "compiled_units",
            "observed_invocations",
            "qt_version",
            "observed_sha256",
        },
    )
    require(
        digest == sha(observed_pin) == positive["observed_sha256"],
        "Observed independent pin mismatch",
    )
    observed = parse(raw)
    require(isinstance(observed, dict), "Observed object required")
    observed = exact(
        observed,
        {"schema", "records", "qt", "input_origins", "config", "config_sha256"}
        | ({"aliases"} if observed.get("schema") == 2 else set()),
    )
    require(
        type(observed["schema"]) is int and observed["schema"] in (1, 2),
        "Observed schema",
    )
    config = exact(observed["config"], {"schema", "source", "build", "sdk"})
    require(
        type(config["schema"]) is int
        and config["schema"] == 1
        and config["sdk"] == PROFILE["sdk_root"],
        "Config profile mismatch",
    )
    require(
        observed["config_sha256"] == hashlib.sha256(retained_json(config)).hexdigest(),
        "Config hash mismatch",
    )
    roots = exact(report["roots"], {"source", "build", "sdk"})
    require(
        config["source"] == roots["source"] and config["build"] == roots["build"],
        "Config roots mismatch",
    )
    for path in (*roots.values(), config["sdk"]):
        require(
            isinstance(path, str)
            and Path(path).is_absolute()
            and ".." not in Path(path).parts,
            "Invalid captured root",
        )
    root_paths = [Path(path) for path in roots.values()]
    require(
        all(
            not a.is_relative_to(b) and not b.is_relative_to(a)
            for i, a in enumerate(root_paths)
            for b in root_paths[:i]
        ),
        "Overlapping captured roots",
    )
    rows = sequence(record["files"])
    by_id = {}
    by_path = {}
    for row in rows:
        exact(row, {"id", "root", "path", "kind", "sha256"})
        identity(row["id"])
        relative(row["path"])
        sha(row["sha256"])
        require(
            row["root"] in roots
            and row["id"] not in by_id
            and (row["root"], row["path"]) not in by_path,
            "Input whitelist conflict",
        )
        by_id[row["id"]] = row
        by_path[row["root"], row["path"]] = row
    origins = observed["input_origins"]
    require(isinstance(origins, dict) and len(origins) <= 4096, "Origins cap/schema")
    for origin, staged in origins.items():
        require(
            isinstance(origin, str)
            and Path(origin).is_absolute()
            and ".." not in Path(origin).parts
            and any(
                Path(origin).is_relative_to(Path(base))
                for base in (PROFILE["sdk_root"], PROFILE["registry_source_root"])
            ),
            "Input origin outside profile",
        )
        require(
            staged == hashlib.sha256(origin.encode()).hexdigest()
            and ("sdk", staged) in by_path,
            "Staged input binding mismatch",
        )
    alias_map = validate_aliases(observed.get("aliases", {}), Path(roots["build"]))
    for origin, canonical in alias_map.items():
        key = ("build", Path(canonical).relative_to(Path(roots["build"])).as_posix())
        require(
            key in by_path
            and by_path[key]["kind"] == "generated"
            and by_path[key]["sha256"] == observed["aliases"][origin]["sha256"],
            "Alias outside retained whitelist",
        )
    used = {row["id"] for row in rows if row["kind"] == "elf"}

    def locate(path: str, cwd: str, kind: str | None = None) -> dict:
        require(isinstance(path, str) and isinstance(cwd, str), "Input path type")
        absolute = Path(
            os.path.normpath(
                path if Path(path).is_absolute() else str(Path(cwd) / path)
            )
        )
        absolute = Path(alias_map.get(str(absolute), str(absolute)))
        matches = [
            (root, absolute.relative_to(Path(base)).as_posix())
            for root, base in roots.items()
            if absolute.is_relative_to(Path(base))
        ]
        if not matches:
            require(str(absolute) in origins, "Input missing from origins")
            matches = [("sdk", origins[str(absolute)])]
        require(len(matches) == 1 and matches[0] in by_path, "Input outside whitelist")
        row = by_path[matches[0]]
        inferred = (
            kind
            or {"source": "source", "build": "generated", "sdk": "header"}[row["root"]]
        )
        require(
            row["kind"] == inferred
            or inferred == "header"
            and row["kind"] == "sdk-unit",
            "Input kind binding mismatch",
        )
        used.add(row["id"])
        return row

    records = sequence(observed["records"])
    units = []
    payloads = {}
    dependency_rows = 0
    for number, row in enumerate(records):
        fields = {
            "schema",
            "config_sha256",
            "argv",
            "original_argv",
            "cwd",
            "compiler",
            "exit",
            "stdout_sha256",
            "stderr_sha256",
            "depfile",
            "unit",
            "compiler_id",
        }
        require(isinstance(row, dict), "Observed record должен быть object")
        compiling = row.get("unit") is not None
        if row.get("schema") == 2:
            fields |= {"purpose", "probe"}
        exact(
            row,
            fields
            | ({"raw_depfile_sha256", "normalized_depfile"} if compiling else set()),
        )
        is_probe = validate_purpose(row, Path(roots["build"]))
        require(
            row["config_sha256"] == observed["config_sha256"],
            "Observed config binding mismatch",
        )
        sha(row["stdout_sha256"])
        sha(row["stderr_sha256"])
        cwd = row["cwd"]
        require(
            isinstance(cwd, str)
            and Path(cwd).is_absolute()
            and ".." not in Path(cwd).parts
            and (
                any(
                    Path(cwd).is_relative_to(Path(roots[key]))
                    for key in ("source", "build")
                )
                or cwd in (registry_cwds or set())
            ),
            "Observed cwd outside roots",
        )
        expected_argv = [
            PROFILE["compiler"],
            *(
                row["original_argv"]
                if is_probe
                else compile_arguments(
                    row["original_argv"],
                    Path(roots["build"]) / "p25capture" / f"{number}.d",
                )
            ),
        ]
        require(row["argv"] == expected_argv, "Observed argv binding mismatch")
        compiler = exact(row["compiler"], {"path", "sha256"})
        tool = locate(compiler["path"], roots["sdk"], "tool")
        require(
            tool["id"] == row["compiler_id"]
            and tool["sha256"] == sha(compiler["sha256"]),
            "Compiler input binding mismatch",
        )
        if is_probe or "-c" not in row["original_argv"]:
            require(
                row["unit"] is None and row["depfile"] is None, "Probe binding mismatch"
            )
            continue
        args = [
            arg
            for arg in row["original_argv"]
            if arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++"))
        ]
        require(
            len(args) == 1
            and row["unit"] == str(Path(cwd) / args[0])
            and row["depfile"] == f"p25capture/{number}.d",
            "Observed unit/dep binding mismatch",
        )
        unit = locate(row["unit"], cwd)
        if unit["root"] == "sdk":
            require(unit["kind"] == "sdk-unit", "External compile kind")
        dep = exact(row["normalized_depfile"], {"schema", "unit", "dependencies"})
        deps = ids(dep["dependencies"])
        require(
            type(dep["schema"]) is int
            and dep["schema"] == 1
            and dep["unit"] == unit["id"]
            and unit["id"] in deps,
            "Normalized dep binding mismatch",
        )
        sha(row["raw_depfile_sha256"])
        dependency_rows += len(deps)
        require(dependency_rows <= PROFILE["dependency_row_cap"], "Dependency cap")
        for key in deps:
            require(
                key in by_id
                and by_id[key]["kind"] in {"source", "generated", "header", "sdk-unit"},
                "Dependency outside whitelist",
            )
            used.add(key)
        dep_row = locate(
            str(Path(roots["build"]) / f"p25capture/{number}-normalized.json"),
            cwd,
            "depfile",
        )
        payloads[dep_row["id"]] = retained_json(dep)
        units.append(
            {"file": unit["id"], "depfile": dep_row["id"], "argv": row["argv"]}
        )
    require(
        record["units"] == units
        and record["generated"] == []
        and record["primary_refs"] == [],
        "Compile/generated closure conflict",
    )
    qt = exact(
        observed["qt"],
        {"schema", "query_argv", "version", "exit", "tool", "stdout", "stderr_sha256"},
    )
    require(
        type(qt["schema"]) is int
        and qt["schema"] == 1
        and type(qt["exit"]) is int
        and qt["exit"] == 0
        and qt["query_argv"] == PROFILE["qt_query"]
        and isinstance(qt["version"], str)
        and re.fullmatch(r"\d+\.\d+\.\d+", qt["version"]) is not None
        and qt["stdout"].strip() == qt["version"],
        "Qt observed binding mismatch",
    )
    sha(qt["stderr_sha256"])
    tool = exact(qt["tool"], {"path", "sha256"})
    query = locate(tool["path"], roots["sdk"], "tool")
    require(query["sha256"] == sha(tool["sha256"]), "Qt tool binding mismatch")
    qt_row = locate(
        str(Path(roots["build"]) / "p25capture/qt-normalized.json"),
        roots["build"],
        "qt-version",
    )
    require(record["qt_version"] == qt_row["id"], "Qt record binding mismatch")
    payloads[qt_row["id"]] = retained_json(
        {
            "schema": 1,
            "version": qt["version"],
            "sdk_files": [row["id"] for row in rows if row["root"] == "sdk"],
            "query_argv": qt["query_argv"],
            "query_tool": query["id"],
            "exit": 0,
        }
    )
    require(used == set(by_id), "Unobserved input whitelist entry")
    require(
        record["source"]["tracked_inputs"]
        == [row["id"] for row in rows if row["root"] == "source"],
        "Tracked input binding mismatch",
    )
    missing = ["qt:query-to-header-version-join"]
    if not units:
        missing.append("cxx:invocations")
    for row in rows:
        if row["kind"] == "generated":
            missing.append(f"generation-provenance:{row['id']}")
        if row["kind"] in ("header", "sdk-unit"):
            missing.append(f"source-offer-primary-join:{row['id']}")
    require(
        positive
        == {
            "producer_missing": missing,
            "compiled_units": len(units),
            "observed_invocations": len(records),
            "qt_version": qt["version"],
            "observed_sha256": digest,
        }
        and manifest["producer_missing"] == missing,
        "Positive metadata conflict",
    )
    require(
        type(positive["compiled_units"]) is int
        and type(positive["observed_invocations"]) is int,
        "Positive counters schema",
    )
    require(
        same(report["files"], [dict(row, verified=True) for row in rows]),
        "Captured file identity conflict",
    )
    require(
        same(
            report["compile_units"],
            [
                dict(unit, normalized_depfile=records_dep)
                for unit, records_dep in zip(
                    units,
                    [
                        row["normalized_depfile"]
                        for row in records
                        if row["unit"] is not None
                    ],
                    strict=True,
                )
            ],
        ),
        "Captured deps conflict",
    )
    require(report["generated_sources"] == [], "Unexpected generation provenance")
    for item in sequence(report["unbound_generated_sources"]):
        exact(
            item,
            {
                "file",
                "text",
                "generation_record",
                "expressions",
                "primary_refs",
                "applicability",
                "copyright_excerpt",
            },
        )
        file = item["file"]
        require(
            file["id"] in by_id
            and same(file, dict(by_id[file["id"]], verified=True))
            and file["kind"] == "generated"
            and item["generation_record"] is None
            and isinstance(item["text"], str),
            "Generated capture binding mismatch",
        )
        require(file["id"] not in payloads, "Duplicate generated capture")
        payloads[file["id"]] = item["text"].encode()
    require(
        {item["file"]["id"] for item in report["unbound_generated_sources"]}
        == {row["id"] for row in rows if row["kind"] == "generated"},
        "Missing generated capture",
    )
    for key, raw in payloads.items():
        require(
            hashlib.sha256(raw).hexdigest() == by_id[key]["sha256"],
            "Retained capture bytes mismatch",
        )
        reader.virtual[by_id[key]["root"], by_id[key]["path"]] = raw
    reader.enriched_paths = {(row["root"], row["path"]) for row in rows}
    replay = _capture(reader, "capture-record.json", manifest["record_sha256"])
    # Недоступные SDK/source/tool bytes не переименовываются в verified bytes.
    require(
        same(report["unbound_generated_sources"], replay["unbound_generated_sources"]),
        "Generated capture conditions mismatch",
    )
    require(
        same(
            report["qt_binding"],
            {
                "record": dict(qt_row, verified=True),
                "metadata": parse(payloads[qt_row["id"]]),
                "query_tool": dict(query, verified=True),
            },
        )
        and report["qt_version"] == qt["version"],
        "Captured Qt conflict",
    )
    header_ids = set()
    for item in sequence(report["headers"]):
        exact(
            item,
            {
                "source_ref",
                "file",
                "expressions",
                "primary_refs",
                "applicability",
                "copyright_excerpt",
            },
        )
        file = item["file"]
        require(
            file["id"] in by_id
            and same(file, dict(by_id[file["id"]], verified=True))
            and file["kind"] in ("header", "sdk-unit")
            and item["source_ref"] is None
            and item["primary_refs"] == {}
            and item["applicability"] == "NOTPROVEN",
            "Header capture binding mismatch",
        )
        require(file["id"] not in header_ids, "Duplicate header")
        header_ids.add(file["id"])
        for key in ("expressions", "copyright_excerpt"):
            require(
                all(isinstance(value, str) for value in sequence(item[key])),
                "Header text schema",
            )
    require(
        header_ids
        == {row["id"] for row in rows if row["kind"] in ("header", "sdk-unit")},
        "Header whitelist mismatch",
    )
    require(
        report["schema"] == 1
        and type(report["schema"]) is int
        and report["source"] == record["source"]
        and report["record_sha256"] == manifest["record_sha256"]
        and same(report["elf_profile_binding"], replay["elf_profile_binding"])
        and report["binding_scope"] == replay["binding_scope"]
        and report["legal_status"] == "NOTPROVEN"
        and report["final_linux_acceptance"] is False
        and report["production_admission_gate"] is False,
        "Report closure conflict",
    )
    require(
        report["status"] == manifest["status"] == "MISSING"
        and report["missing"] == manifest["missing"]
        and isinstance(report["missing"], list)
        and report["missing"] == sorted(set(report["missing"]))
        and bool(report["missing"])
        and all(
            isinstance(item, str) and len(item) <= 4096 for item in report["missing"]
        ),
        "Missing closure schema",
    )
    expected_missing = {"generatedrecord"}
    if not units:
        expected_missing.add("depfiles")
    if not header_ids:
        expected_missing.add("headeridentity")
    covered = {
        key
        for row in records
        if row["unit"] is not None
        for key in row["normalized_depfile"]["dependencies"]
    }
    for item in [*report["headers"], *report["unbound_generated_sources"]]:
        key = item["file"]["id"]
        if item["file"]["kind"] in ("header", "sdk-unit"):
            expected_missing.add(f"header_source:{key}")
            if key not in covered:
                expected_missing.add(f"header_depfile_coverage:{key}")
        else:
            expected_missing.add(f"generated_record:{key}")
        tokens = {
            token
            for expression in item["expressions"]
            for token in re.findall(r"[A-Za-z0-9_.+-]+", expression)
        } - {"OR", "AND", "WITH"}
        if not item["expressions"] or not tokens:
            expected_missing.add(f"SPDX:{key}")
        expected_missing.update(f"primary:{key}:{token}" for token in tokens)
    require(
        report["missing"] == sorted(expected_missing),
        "Captured missing conditions conflict",
    )
    # Original report остаётся pinned evidence; replay честно добавляет unavailable files.
    replay["missing"] = sorted(
        set(replay["missing"])
        | set(report["missing"])
        | {"retained:raw-depfiles-unavailable"}
    )
    replay["status"] = "MISSING"
    return replay


def produce(
    retained: Path,
    pins: dict[str, str],
    source_commit: str,
    *,
    registry_proof: str | None = None,
    registry_proof_sha256: str | None = None,
) -> tuple[dict, dict]:
    """Pins передаются из независимого доверенного канала, никогда из самого marker."""
    require(
        set(pins)
        in (
            {*METADATA, "source.tar"},
            {*METADATA, "source.tar", "build-cxx-observed.json"},
        ),
        "Нужны все independent pins",
    )
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None, "Неверный commit")
    require(".." not in retained.parts, "Parent traversal in retained root")
    reader = RetainedReader(retained)
    values = {}
    for name in METADATA:
        digest, raw = reader.read_file(
            name, 32 * MAX_METADATA if name.endswith("report.json") else MAX_METADATA
        )
        require(digest == sha(pins[name]), "Independent pin mismatch: " + name)
        values[name] = parse(raw)
    archive, _ = reader.read_file("source.tar", MAX_SOURCE, False)
    require(archive == sha(pins["source.tar"]), "Source archive pin mismatch")
    frozen = values["frozen.json"]
    fields = {
        "schema",
        "release_id",
        "state",
        "source",
        "archive_sha256",
        "recipe",
        "tooling_sha256",
    }
    enriched = "final_profile" in frozen
    if enriched:
        fields.add("final_profile")
    require(
        ("build-cxx-observed.json" in pins) == enriched,
        "Final observed independent pin required",
    )
    exact(frozen, fields)
    require(
        type(frozen["schema"]) is int
        and frozen["schema"] == 2
        and frozen["state"] == "FROZEN",
        "Неверный frozen schema/state",
    )
    exact(frozen["source"], {"commit", "tree"})
    require(
        frozen["source"]["commit"] == source_commit
        and re.fullmatch(r"[0-9a-f]{40}", frozen["source"]["tree"]) is not None,
        "Stale source",
    )
    require(
        frozen["recipe"] == RECIPE and frozen["archive_sha256"] == archive,
        "Неверный frozen profile/archive",
    )
    require(
        isinstance(frozen["tooling_sha256"], dict) and bool(frozen["tooling_sha256"]),
        "Нет tooling pins",
    )
    for pin in frozen["tooling_sha256"].values():
        sha(pin)
    exact(values["rust-captured-only.json"]["toolchains"], {"cargo", "rustc"})
    marker = values["rust-captured-only.json"]
    require(
        type(marker["schema"]) is int and marker["schema"] == 2,
        "Неверный marker schema",
    )
    for version in marker["toolchains"].values():
        require(
            isinstance(version, str) and 0 < len(version) <= 4096, "Неверный toolchain"
        )
    require(
        isinstance(marker["controlled_env"], dict)
        and set(marker["controlled_env"]) <= set(CONTROLLED_ENV),
        "Неверный environment",
    )
    require(type(frozen["recipe"]["schema"]) is int, "Неверный recipe schema")
    require(
        isinstance(marker["commands"], list) and len(marker["commands"]) <= 4096,
        "Command bounds",
    )
    for command in marker["commands"]:
        exact(command, {"argv", "cwd", "exit", "controlled_env"})
        require(
            isinstance(command["argv"], list)
            and 0 < len(command["argv"]) <= 4096
            and all(
                isinstance(arg, str) and 0 < len(arg) <= 4096 and "\x00" not in arg
                for arg in command["argv"]
            ),
            "Неверные command args",
        )
        require(
            isinstance(command["controlled_env"], dict)
            and set(command["controlled_env"]) <= set(CONTROLLED_ENV)
            and all(
                isinstance(value, str) for value in command["controlled_env"].values()
            ),
            "Неверный command environment",
        )
    exact(
        marker,
        fields
        | {
            "producer",
            "toolchains",
            "controlled_env",
            "commands",
            "elf",
            "build_capture",
            "rust_lineage",
            "final_linux_acceptance",
        },
    )
    require(
        all(
            same(marker[key], value) for key, value in frozen.items() if key != "state"
        ),
        "Stale frozen marker",
    )
    require(
        marker["state"] == "RUST_CAPTURED_ONLY"
        and marker["producer"] == "local-release-controller-v1"
        and marker["rust_lineage"] is None
        and marker["final_linux_acceptance"] is False,
        "Не actual Rust capture",
    )
    manifest = values["build-capture-manifest.json"]
    exact(
        manifest,
        ({"positive_metadata", "final_profile"} if enriched else set())
        | {
            "schema",
            "status",
            "missing",
            "producer_missing",
            "source",
            "observed_commands",
            "record_sha256",
            "report_sha256",
            "elfs",
            "final_linux_acceptance",
            "legal_status",
            "production_admission_gate",
            "invocation",
        },
    )
    require(same(marker["build_capture"], manifest), "Capture marker conflict")
    require(
        manifest["record_sha256"] == pins["build-capture-record.json"]
        and manifest["report_sha256"] == pins["build-capture-report.json"],
        "Capture pins conflict",
    )
    record = values["build-capture-record.json"]
    tracked = record["source"].get("tracked_inputs", []) if enriched else []
    require(
        record["source"]
        == {**frozen["source"], "archive_sha256": archive, "tracked_inputs": tracked},
        "Source binding отсутствует",
    )
    commands = [[SLOT, *command] for command in RECIPE["rust_commands"]]
    require(
        record["profile"]
        == {"target": RECIPE["target"], "commands": commands, "features": ["gui"]},
        "Profile mismatch",
    )
    for key, expected in (
        {}
        if enriched
        else {
            "units": [],
            "generated": [],
            "primary_refs": [],
            "qt_version": None,
        }
    ).items():
        require(record.get(key, "MISSING") == expected, "Неподдерживаемая closure")
    observed = manifest["observed_commands"]
    require(
        isinstance(observed, list) and len(observed) == len(commands),
        "Нет observed closure",
    )
    for row, command in zip(observed, commands, strict=True):
        exact(row, {"argv", "cwd", "exit", "controlled_env"})
        require(
            row["argv"] == command
            and type(row["exit"]) is int
            and row["exit"] == 0
            and isinstance(row["cwd"], str)
            and row["cwd"].startswith("/"),
            "Неверный observed build",
        )
    require(
        len({row["cwd"] for row in observed}) == 1
        and marker["commands"][-len(observed) :] == observed,
        "Command closure conflict",
    )
    expected_files = [
        {
            "id": f"elf-{i}",
            "root": "build",
            "path": "release/" + name,
            "kind": "elf",
            "sha256": sha(row["sha256"]),
        }
        for i, (name, row) in enumerate(
            zip(
                RUST,
                [row for row in record["files"] if row["kind"] == "elf"],
                strict=True,
            )
        )
    ]
    require(
        (enriched or record["files"] == expected_files)
        and manifest["elfs"] == expected_files,
        "ELF whitelist conflict",
    )
    report = values["build-capture-report.json"]
    require(
        (registry_proof is None) == (registry_proof_sha256 is None),
        "Registry proof path/pin pair required",
    )
    registry_cwds = set()
    if enriched:
        _, observed_raw = reader.read_file("build-cxx-observed.json", 8 * MAX_METADATA)
        observed_evidence = parse(observed_raw)
        roots = report["roots"]
        needs_registry = any(
            isinstance(row, dict)
            and isinstance(row.get("cwd"), str)
            and not any(
                Path(row["cwd"]).is_relative_to(Path(roots[key]))
                for key in ("source", "build")
            )
            for row in sequence(observed_evidence["records"])
        )
        require(
            not needs_registry or registry_proof is not None,
            "MISSING: independently pinned registry proof",
        )
    else:
        needs_registry = False
    require(registry_proof is None or needs_registry, "Unexpected registry proof")
    if registry_proof is not None:
        from n5_registry_source_proof import validate

        registry_cwds, payloads = validate(
            reader, registry_proof, registry_proof_sha256, pins, source_commit
        )
        reader.virtual.update(payloads)
    replay = (
        final_capture(
            reader,
            frozen,
            manifest,
            record,
            report,
            pins["build-cxx-observed.json"],
            registry_cwds,
        )
        if enriched
        else _capture(reader, "capture-record.json", pins["build-capture-record.json"])
    )
    require(
        set(report) == set(replay) | {"roots", "record_path"}, "Report schema mismatch"
    )
    require(
        enriched
        or all(
            same(report[key], value)
            for key, value in replay.items()
            if key != "read_bytes"
        ),
        "Closure replay mismatch",
    )
    require(report["record_path"] == "capture-record.json", "Report record mismatch")
    require(
        manifest["schema"] == 1
        and type(manifest["schema"]) is int
        and manifest["status"] == replay["status"]
        and (enriched or manifest["missing"] == replay["missing"])
        and manifest["source"] == record["source"]
        and (enriched or manifest["producer_missing"] == PRODUCER_MISSING)
        and manifest["final_linux_acceptance"] is False
        and manifest["production_admission_gate"] is False
        and manifest["legal_status"] == "NOTPROVEN",
        "Closure manifest mismatch",
    )
    exact(report["roots"], {"source", "build", "sdk"})
    require(
        all(
            isinstance(path, str) and path.startswith("/")
            for path in report["roots"].values()
        ),
        "Неверные report roots",
    )
    require(
        type(report["schema"]) is int
        and type(report["read_bytes"]) is int
        and 0 < report["read_bytes"] <= 1024**3,
        "Неверный report schema/bounds",
    )
    require(
        manifest["invocation"]
        == [
            "python3",
            "tools/p25_capture_build_closure.py",
            "--source-root",
            report["roots"]["source"],
            "--build-root",
            report["roots"]["build"],
            "--sdk-root",
            report["roots"]["sdk"],
            "--record",
            "capture-record.json",
            "--record-sha256",
            pins["build-capture-record.json"],
        ],
        "Invocation mismatch",
    )
    require(observed[0]["cwd"] == report["roots"]["source"], "Source cwd mismatch")
    receipts = {}
    require(set(marker["elf"]) == set(RUST), "Marker ELF whitelist mismatch")
    for role, name in ROLES.items():
        digest, _ = reader.read_file(name, MAX_ELF, False)
        fd = open_regular(retained / name)
        try:
            header = elf_header(os.read(fd, 64), os.fstat(fd).st_size)
        finally:
            os.close(fd)
        require(header == marker["elf"][name], "ELF header mismatch")
        receipts[role + ".receipt.json"] = {
            "schema": "SOURCE_BOUND_ELF_V1",
            "source_commit": source_commit,
            "source_archive_sha256": archive,
            "elf_sha256": digest,
        }
    receipts["worker-build-receipt.json"] = {
        "schema": 1,
        "worker_sha256": receipts["worker.receipt.json"]["elf_sha256"],
        "source_archive_sha256": archive,
    }
    # Повторно проверяем все пути после join, включая подмену ранее прочитанного файла.
    for name, digest in list(reader.seen.items()):
        actual, _ = reader.read_file(
            name, MAX_SOURCE if name == "source.tar" else MAX_ELF, False
        )
        require(actual == digest, "Вход изменился после join")
    return receipts, {
        "status": "UNREGISTERED",
        "admission": "NOT_ADMISSION",
        "binding": "projection_of_externally_trusted_controller_build_evidence",
        "independent_compile_attestation": False,
        "independent_pins": pins,
        **(
            {
                "registry_proof": {
                    "path": registry_proof,
                    "sha256": registry_proof_sha256,
                }
            }
            if registry_proof is not None
            else {}
        ),
        "source_commit": source_commit,
        "source_archive_sha256": archive,
        "closure_status": replay["status"],
        "capture_profile": "p25-final-cxx-v1" if enriched else "original-rust-only",
        "unavailable_input_bytes": [
            row["id"] for row in replay["files"] if not row["verified"]
        ],
        "capture_byte_replay": "retained-registry-generated-and-normalized-metadata"
        if registry_proof is not None
        else "retained-generated-and-normalized-metadata"
        if enriched
        else "retained-elf-only",
        "closure_missing": replay["missing"],
        "driver": "MISSING",
        "receipt_sha256": {
            name: hashlib.sha256(encode(value)).hexdigest()
            for name, value in receipts.items()
        },
    }


def emit(output: Path, receipts: dict, report: dict) -> None:
    """Новый каталог в workspace, fsync; существующее имя никогда не заменяется."""
    require(
        set(receipts)
        == {*(role + ".receipt.json" for role in ROLES), "worker-build-receipt.json"},
        "Неверный набор outputs",
    )
    require(".." not in output.parts, "Parent traversal in output")
    output = Path(os.path.abspath(output))
    workspace = Path.cwd()
    require(
        output.is_relative_to(workspace) and output != workspace, "Выход вне workspace"
    )
    require(
        not any(
            output.is_relative_to(Path(p))
            for p in (
                "/etc",
                "/usr",
                "/dev",
                "/proc",
                "/sys",
                "/run",
                "/boot",
                "/var/lib",
                "/var/cache",
            )
        ),
        "Системный output",
    )
    payloads = {
        name: encode(value)
        for name, value in {**receipts, "report.json": report}.items()
    }
    parent = open_regular_directory(output.parent)
    try:
        require(os.fstat(parent).st_uid == os.geteuid(), "Чужой parent")
        os.mkdir(output.name, 0o700, dir_fd=parent)
        directory = os.open(
            output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            for name, raw in payloads.items():
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(directory)
            os.fsync(parent)
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    for name in (*METADATA, "source.tar", "build-cxx-observed.json"):
        parser.add_argument(
            "--" + name.replace(".", "-") + "-sha256",
            dest=name,
            required=name != "build-cxx-observed.json",
        )
    parser.add_argument("--registry-proof")
    parser.add_argument("--registry-proof-sha256")
    args = vars(parser.parse_args())
    try:
        receipts, report = produce(
            args["retained"],
            {
                name: args[name]
                for name in (*METADATA, "source.tar", "build-cxx-observed.json")
                if args[name] is not None
            },
            args["source_commit"],
            registry_proof=args["registry_proof"],
            registry_proof_sha256=args["registry_proof_sha256"],
        )
        emit(args["output"], receipts, report)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        parser.exit(2, f"Capture отклонён: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
