"""Pure post-capture attribution attachment; никаких I/O, election или admission."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

from p25_capture_build_closure import (
    KINDS,
    MAX_FILES,
    MAX_METADATA,
    CaptureError,
    identity,
    object_fields,
    parse,
    relative,
    require,
    sequence,
    sha,
)

MANIFEST_FIELDS = set(
    "schema status missing producer_missing source observed_commands record_sha256 report_sha256 elfs final_linux_acceptance legal_status production_admission_gate invocation positive_metadata final_profile".split()
)
RECORD_FIELDS = set(
    "schema source profile files elfs qt_version units generated primary_refs".split()
)
REPORT_FIELDS = set(
    "schema status missing legal_status final_linux_acceptance production_admission_gate record_sha256 source elf_profile_binding qt_version qt_binding compile_units binding_scope headers generated_sources unbound_generated_sources files read_bytes roots record_path".split()
)
CANDIDATE_FIELDS = set(
    "schema producer_review_ref scope final_linux_acceptance legal_status packages license_directory_aliases qconfig_version headers selected_primary_text_matches historical_qt_primary_refs retained_source_offer cxx_generator_candidates single_missing_input".split()
)
HEADER_FIELDS = set(
    "id origin_path sha256 bytes installed_package package_version package_mtree_match qt_version_candidate spdx_expressions notice_excerpt gpl3_compatible_candidates source_fragment version_exact_source_offer_counterpart scope final_capture_join legal_status forwarding_include QT_VERSION_STR reason_no_automatic_license".split()
)
OBSERVED_FIELDS = set("schema records qt input_origins config config_sha256".split())
OBSERVED_RECORD_FIELDS = set(
    "schema config_sha256 argv original_argv cwd compiler exit depfile unit stdout_sha256 stderr_sha256 compiler_id normalized_depfile".split()
)
FILE_FIELDS = set("id root path kind sha256 source_ref".split())
CODE_KINDS = {"source", "sdk-source", "header", "sdk-unit", "generated"}


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _document(
    raw: bytes,
    cap: int,
    fields: set[str],
    required: set[str],
    schemas: tuple[int, ...] = (1,),
) -> dict:
    require(isinstance(raw, bytes) and len(raw) <= cap, "JSON byte cap/type")
    doc = object_fields(parse(raw), fields, required | {"schema"})
    require(type(doc["schema"]) is int and doc["schema"] in schemas, "Unknown schema")
    return doc


def _absolute(path: Any) -> str:
    require(isinstance(path, str) and path.startswith("/"), "Не absolute origin/root")
    relative(path[1:])
    return path


def _files(rows: Any, verified: bool = False) -> dict[str, dict]:
    result = {}
    paths = set()
    for row in sequence(rows):
        object_fields(
            row,
            FILE_FIELDS | ({"verified"} if verified else set()),
            {"id", "root", "path", "kind"} | ({"verified"} if verified else set()),
        )
        key = identity(row["id"])
        require(key not in result, "Duplicate file ID")
        relative(row["path"])
        pair = (row["root"], row["path"])
        require(pair not in paths, "Duplicate file path")
        paths.add(pair)
        require(
            row["kind"] in KINDS
            and (
                row["root"] == KINDS[row["kind"]]
                or row["kind"] == "tool"
                and row["root"] == "build"
            ),
            "File kind/root mismatch",
        )
        if "sha256" in row:
            sha(row["sha256"])
        if verified:
            require(type(row["verified"]) is bool, "Invalid verified flag")
            require(
                not row["verified"] or "sha256" in row, "Verified file without hash"
            )
        result[key] = row
    return result


def _supplied(values: Mapping[str, bytes], total_cap: int) -> None:
    require(
        isinstance(values, Mapping) and len(values) <= MAX_FILES,
        "Supplied bytes map cap",
    )
    total = 0
    for key, raw in values.items():
        require(
            isinstance(key, str)
            and len(key) <= 4096
            and isinstance(raw, bytes)
            and len(raw) <= MAX_METADATA,
            "Supplied blob cap/type",
        )
        total += len(raw)
        require(total <= total_cap, "Supplied bytes total cap")


def attribute_capture(
    *,
    manifest: bytes,
    manifest_sha256: str,
    record: bytes,
    report: bytes,
    observed: bytes,
    candidates: bytes,
    candidates_sha256: str,
    source_fragments: Mapping[str, bytes],
    primary_texts: Mapping[str, bytes],
) -> dict:
    """Caller pins manifest/candidates независимо; bytes не дают provenance authority.

    Все arguments уже retained bytes. Функция не открывает пути из JSON. Pins/
    malformed schema отвергаются CaptureError; attribution gaps классифицируются
    в отдельном report, исходный capture статус никогда не переписывается.
    """
    try:
        return _attribute(
            manifest,
            sha(manifest_sha256),
            record,
            report,
            observed,
            candidates,
            sha(candidates_sha256),
            source_fragments,
            primary_texts,
        )
    except CaptureError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise CaptureError("Invalid attribution structure") from error


def _attribute(
    manifest_raw: bytes,
    manifest_pin: str,
    record_raw: bytes,
    report_raw: bytes,
    observed_raw: bytes,
    candidate_raw: bytes,
    candidate_pin: str,
    fragments: Mapping[str, bytes],
    primary_bytes: Mapping[str, bytes],
) -> dict:
    require(
        isinstance(manifest_raw, bytes)
        and len(manifest_raw) <= MAX_METADATA
        and _hash(manifest_raw) == manifest_pin,
        "Manifest pin/cap mismatch",
    )
    require(
        isinstance(candidate_raw, bytes)
        and len(candidate_raw) <= 4 * MAX_METADATA
        and _hash(candidate_raw) == candidate_pin,
        "Candidate pin/cap mismatch",
    )
    manifest = _document(
        manifest_raw,
        MAX_METADATA,
        MANIFEST_FIELDS,
        {"source", "record_sha256", "report_sha256", "positive_metadata", "elfs"},
    )
    for raw, expected, cap in (
        (record_raw, manifest["record_sha256"], MAX_METADATA),
        (report_raw, manifest["report_sha256"], 32 * MAX_METADATA),
        (
            observed_raw,
            manifest["positive_metadata"]["observed_sha256"],
            8 * MAX_METADATA,
        ),
    ):
        require(
            isinstance(raw, bytes) and len(raw) <= cap and _hash(raw) == sha(expected),
            "Retained input pin/cap mismatch",
        )
    record = _document(
        record_raw,
        MAX_METADATA,
        RECORD_FIELDS,
        {"source", "profile", "files", "elfs", "units"},
    )
    report = _document(
        report_raw,
        32 * MAX_METADATA,
        REPORT_FIELDS,
        {
            "source",
            "record_sha256",
            "files",
            "roots",
            "compile_units",
            "elf_profile_binding",
            "legal_status",
            "final_linux_acceptance",
        },
    )
    observed = _document(
        observed_raw,
        8 * MAX_METADATA,
        OBSERVED_FIELDS | {"aliases"},
        {"records", "input_origins", "config"},
        (1, 2),
    )
    candidate = _document(
        candidate_raw,
        4 * MAX_METADATA,
        CANDIDATE_FIELDS,
        {"headers", "selected_primary_text_matches", "single_missing_input"},
    )
    require(
        report["record_sha256"] == _hash(record_raw)
        and manifest["source"] == record["source"] == report["source"],
        "Source/record binding mismatch",
    )
    require(
        report["legal_status"] == "NOTPROVEN"
        and report["final_linux_acceptance"] is False,
        "Unexpected legal promotion",
    )
    require(
        report["elf_profile_binding"]["profile"] == record["profile"],
        "Profile binding mismatch",
    )
    roots = object_fields(
        report["roots"], {"source", "build", "sdk"}, {"source", "build", "sdk"}
    )
    for root in roots.values():
        _absolute(root)
    require(
        observed["config"]["source"] == roots["source"]
        and observed["config"]["build"] == roots["build"],
        "Observed roots mismatch",
    )
    files, captured = _files(record["files"]), _files(report["files"], True)
    elf_ids = [identity(key) for key in sequence(record["elfs"])]
    require(
        bool(elf_ids)
        and set(elf_ids) == {key for key, row in files.items() if row["kind"] == "elf"},
        "ELF whitelist mismatch",
    )
    require(
        manifest["elfs"] == [files[key] for key in elf_ids], "Manifest ELF mismatch"
    )
    require(
        report["elf_profile_binding"]["elfs"] == [captured[key] for key in elf_ids]
        and all(
            captured[key].get("verified") is True
            and captured[key].get("sha256") == files[key].get("sha256")
            for key in elf_ids
        ),
        "Verified ELF binding missing",
    )
    _supplied(fragments, MAX_METADATA)
    _supplied(primary_bytes, 8 * MAX_METADATA)

    by_origin: dict[str, list[dict]] = defaultdict(list)
    for row in sequence(candidate["headers"]):
        object_fields(
            row,
            HEADER_FIELDS,
            {
                "id",
                "origin_path",
                "sha256",
                "spdx_expressions",
                "notice_excerpt",
                "gpl3_compatible_candidates",
                "source_fragment",
            },
        )
        sha(row["sha256"])
        identity(row["id"])
        by_origin[_absolute(row["origin_path"])].append(row)
    primary_index: dict[str, list[dict]] = defaultdict(list)
    for row in sequence(candidate["selected_primary_text_matches"]):
        primary_index[sha(row["sha256"])].append(row)
    origins: dict[str, list[str]] = defaultdict(list)
    require(
        isinstance(observed["input_origins"], dict)
        and len(observed["input_origins"]) <= MAX_FILES,
        "Origin map cap/type",
    )
    for origin, path in observed["input_origins"].items():
        origins[relative(path)].append(_absolute(origin))

    def dep(value: Any) -> dict | None:
        if value is None:
            return None
        object_fields(
            value,
            {"schema", "unit", "dependencies"},
            {"schema", "unit", "dependencies"},
        )
        require(
            type(value["schema"]) is int and value["schema"] == 1,
            "Unknown depfile schema",
        )
        identity(value["unit"])
        keys = [identity(key) for key in sequence(value["dependencies"])]
        require(
            bool(keys) and len(keys) == len(set(keys)), "Empty/duplicate dependencies"
        )
        return value

    def argv(value: Any) -> tuple[str, ...]:
        values = sequence(value)
        require(
            bool(values)
            and all(
                isinstance(arg, str) and 0 < len(arg) <= 4096 and "\x00" not in arg
                for arg in values
            ),
            "Invalid argv",
        )
        return tuple(values)

    from pathlib import Path

    from _p25_final_profile import validate_observed_extensions

    validate_observed_extensions(observed, record["files"])
    observed_units: dict[tuple, list[dict]] = defaultdict(list)

    from _p25_final_profile import validate_purpose

    for row in sequence(observed["records"]):
        require(isinstance(row, dict), "Observed record type")
        object_fields(
            row,
            OBSERVED_RECORD_FIELDS
            | (
                {"purpose", "probe", "raw_depfile_sha256"}
                if row.get("schema") == 2
                else set()
            ),
            {"argv", "compiler", "exit"}
            | ({"normalized_depfile"} if row.get("schema") != 2 else set()),
        )
        object_fields(row["compiler"], {"path", "sha256"}, {"path", "sha256"})
        _absolute(row["compiler"]["path"])
        sha(row["compiler"]["sha256"])
        argv(row["argv"])
        require(type(row["exit"]) is int, "Invalid observed exit")
        if "schema" in row:
            validate_purpose(row, Path(observed["config"]["build"]))
        else:
            require(row["exit"] == 0, "Unsuccessful legacy observation")
        if "original_argv" in row:
            argv(row["original_argv"])
        if "compiler_id" in row:
            identity(row["compiler_id"])
        for field in ("cwd", "unit"):
            if field in row and row[field] is not None:
                _absolute(row[field])
        if row.get("depfile") is not None:
            relative(row["depfile"])
        for field in ("config_sha256", "stdout_sha256", "stderr_sha256"):
            if field in row:
                sha(row[field])
        normalized = dep(row.get("normalized_depfile"))
        if normalized is not None:
            observed_units[(normalized["unit"], argv(row["argv"]))].append(row)
    record_units = {}
    for unit in sequence(record["units"]):
        object_fields(unit, {"file", "depfile", "argv"}, {"file", "depfile"})
        key = (identity(unit["file"]), unit["depfile"])
        require(key not in record_units, "Duplicate record unit")
        record_units[key] = unit
    uses: dict[str, list[dict]] = defaultdict(list)
    unit_results = []
    seen_units = set()
    rows_count = 0
    for unit in sequence(report["compile_units"]):
        object_fields(
            unit,
            {"file", "depfile", "argv", "normalized_depfile"},
            {"file", "depfile", "normalized_depfile"},
        )
        key = (identity(unit["file"]), unit["depfile"])
        require(key not in seen_units, "Duplicate reported unit")
        seen_units.add(key)
        normalized = dep(unit["normalized_depfile"])
        issues = []
        declaration = record_units.get(key)
        if declaration is None or declaration != {
            k: v for k, v in unit.items() if k != "normalized_depfile"
        }:
            issues.append("conflicting:record_unit")
        if normalized is None or not unit.get("argv"):
            issues.append("missing:compile_depfile")
        else:
            matches = observed_units.get((key[0], argv(unit["argv"])), [])
            if not matches:
                issues.append("missing:observed_compile")
            elif (
                len(matches) != 1
                or matches[0]["normalized_depfile"] != normalized
                or type(matches[0].get("exit")) is not int
                or matches[0]["exit"] != 0
            ):
                issues.append("conflicting:observed_compile")
            if len(matches) == 1:
                observation = matches[0]
                compiler = captured.get(observation.get("compiler_id"))
                if compiler is None or not compiler["verified"]:
                    issues.append("missing:compiler_identity")
                elif (
                    compiler["kind"] != "tool"
                    or {k: v for k, v in compiler.items() if k != "verified"}
                    != files.get(compiler["id"])
                    or compiler.get("sha256")
                    != observation.get("compiler", {}).get("sha256")
                ):
                    issues.append("conflicting:compiler_identity")
            if normalized["unit"] != key[0] or key[0] not in normalized["dependencies"]:
                issues.append("conflicting:depfile_unit")
        depfile = captured.get(unit["depfile"])
        if depfile is None or not depfile["verified"]:
            issues.append("missing:verified_depfile")
        elif depfile["kind"] != "depfile" or {
            k: v for k, v in depfile.items() if k != "verified"
        } != files.get(unit["depfile"]):
            issues.append("conflicting:depfile_identity")
        classification = (
            "CONFLICTING"
            if any(x.startswith("conflicting:") for x in issues)
            else "MISSING"
            if issues
            else "OBSERVED"
        )
        unit_results.append(
            {
                "file": key[0],
                "depfile": key[1],
                "classification": classification,
                "issues": issues,
            }
        )
        if issues:
            continue
        require(normalized is not None, "Missing normalized depfile")
        rows_count += len(normalized["dependencies"])
        require(rows_count <= 10000, "Dependency row total cap")
        for file_id in normalized["dependencies"]:
            require(
                file_id in files
                and file_id in captured
                and files[file_id]["kind"] in CODE_KINDS,
                "Dependency outside code whitelist",
            )
            uses[file_id].append({"unit": key[0], "depfile": key[1]})
    require(seen_units == set(record_units), "Report omits record units")
    result_rows = []
    output_bytes = 0

    def charge(value: Any) -> None:
        nonlocal output_bytes
        # Refs могут повторяться у многих used files. Ограничиваем fan-out до
        # финальной сериализации, а не после выделения огромной JSON string.
        output_bytes += len(json.dumps(value, ensure_ascii=False).encode())
        require(output_bytes <= 8 * MAX_METADATA, "Attribution output cap")

    for file_id, used_by in uses.items():
        row, original = captured[file_id], files[file_id]
        result = {
            "file_id": file_id,
            "kind": original["kind"],
            "root": original["root"],
            "path": original["path"],
            "sha256": row.get("sha256"),
            "used_by": used_by,
            "classification": "UNKNOWN",
            "issues": [],
            "candidate_options": [],
        }
        issues = result["issues"]
        if {k: v for k, v in row.items() if k != "verified"} != original:
            issues.append("conflicting:record_file_identity")
        if not row["verified"] or "sha256" not in row:
            issues.append("missing:verified_file_hash")
        paths = (
            origins.get(original["path"], [])
            if original["root"] == "sdk"
            else [roots[original["root"]] + "/" + original["path"]]
        )
        if not paths:
            issues.append("missing:origin")
        elif len(paths) != 1:
            issues.append("conflicting:origin_aliases")
        else:
            result["origin_path"] = paths[0]
            matches = by_origin.get(paths[0], [])
            if not matches:
                issues.append("unknown:candidate_origin")
            elif len(matches) != 1:
                issues.append("conflicting:candidate_origin")
            elif matches[0]["sha256"] != row.get("sha256"):
                issues.append("conflicting:candidate_sha256")
            elif not issues:
                item = matches[0]
                result["candidate_id"] = item["id"]
                result["notice_excerpt"] = item["notice_excerpt"]
                result["spdx_expressions"] = item["spdx_expressions"]
                fragment = item["source_fragment"]
                name = relative(fragment["retained_copy"])
                require(
                    sha(fragment["sha256"]) == item["sha256"],
                    "Candidate source fragment identity mismatch",
                )
                raw = fragments.get(name)
                verified = raw is not None and _hash(raw) == item["sha256"]
                result["source_fragment"] = {
                    "path": name,
                    "sha256": item["sha256"],
                    "bytes_verified": verified,
                }
                if verified:
                    try:
                        expressions = re.findall(
                            r"SPDX-License-Identifier:[ \t]*([^\r\n]+)",
                            raw.decode("utf-8"),
                        )
                    except UnicodeError:
                        expressions = None
                    if expressions != item["spdx_expressions"]:
                        issues.append("conflicting:source_spdx_expression")
                if raw is None:
                    issues.append("missing:source_fragment_bytes")
                elif not verified:
                    issues.append("conflicting:source_fragment_bytes")
                for option in sequence(item["gpl3_compatible_candidates"]):
                    identifier, expected = (
                        identity(option["identifier"]),
                        sha(option["primary_sha256"]),
                    )
                    entries = [
                        entry
                        for entry in primary_index.get(expected, [])
                        if entry["identifier"] == identifier
                    ]
                    if len(entries) > 1:
                        issues.append("conflicting:primary_candidates:" + expected)
                    refs = [
                        ref
                        for entry in entries
                        for ref in sequence(entry["retained_offer_matches"])
                    ]
                    tokens = {
                        token
                        for expression in item["spdx_expressions"]
                        for token in re.findall(r"[A-Za-z0-9_.+-]+", expression)
                    }
                    if identifier not in tokens:
                        issues.append("conflicting:candidate_operand:" + identifier)
                    for ref in refs:
                        relative(ref["source_offer_member"])
                    refs_verified = bool(refs) and all(
                        ref.get("verified") is True and ref["sha256"] == expected
                        for ref in refs
                    )
                    if not refs_verified:
                        issues.append("missing:primary_offer_ref:" + expected)
                    if any(ref["sha256"] != expected for ref in refs):
                        issues.append("conflicting:primary_ref_sha256:" + expected)
                    expected_members = sequence(
                        option["available_source_offer_members"]
                    )
                    for member in expected_members:
                        relative(member)
                    members = {ref["source_offer_member"] for ref in refs}
                    if not set(expected_members) <= members:
                        issues.append("missing:primary_offer_member:" + expected)
                    raw = primary_bytes.get(expected)
                    verified = raw is not None and _hash(raw) == expected
                    attached = {
                        "identifier": identifier,
                        "primary_sha256": expected,
                        "primary_refs": refs,
                        "candidate_offer_refs_attested": refs_verified,
                        "bytes_verified": verified,
                    }
                    charge(attached)
                    result["candidate_options"].append(attached)
                    if not refs or raw is None:
                        issues.append("missing:primary:" + expected)
                    elif not verified:
                        issues.append("conflicting:primary:" + expected)
                if not result["candidate_options"] or not item["spdx_expressions"]:
                    issues.append("missing:file_level_license_declaration")
        result["classification"] = (
            "CONFLICTING"
            if any(x.startswith("conflicting:") for x in issues)
            else "MISSING"
            if any(x.startswith("missing:") for x in issues)
            else "UNKNOWN"
            if issues
            else "MATCHED"
        )
        charge(
            {key: value for key, value in result.items() if key != "candidate_options"}
        )
        result_rows.append(result)
    result = {
        "schema": 1,
        "status": "ATTRIBUTION_REPORT",
        "manifest_sha256": manifest_pin,
        "candidate_sha256": candidate_pin,
        "source": record["source"],
        "elfs": manifest["elfs"],
        "units": unit_results,
        "inputs": result_rows,
        "counts": dict(Counter(row["classification"] for row in result_rows)),
        "unused_record_files": len(files) - len(uses),
        "source_capsule": {
            "scope": "candidate source capsule; not a claim of final SDK version or a new legal requirement",
            "classification": "MISSING",
            "input": candidate["single_missing_input"],
        },
        "legal_status": "NOTPROVEN",
        "final_linux_acceptance": False,
        "production_admission_gate": False,
    }
    require(
        len(json.dumps(result, ensure_ascii=False).encode()) <= 8 * MAX_METADATA,
        "Attribution output cap",
    )
    return result
