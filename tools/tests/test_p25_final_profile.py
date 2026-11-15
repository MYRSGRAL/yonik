"""Instrumentation fixtures: никакие реальные compiler/query не запускаются."""

import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _p25_final_profile as p


class FinalProfileTests(unittest.TestCase):
    def _registry_fixture(self, root: Path) -> tuple[Path, Path]:
        import hashlib
        import io
        import tarfile

        source = root / "source"
        source.mkdir(parents=True)
        registry = root / "registry"
        index = "index.crates.io-1949cf8c6b5b557f"
        package = registry / "src" / index / "link-cplusplus-1.0.12"
        (package / "src").mkdir(parents=True)
        data = b"// fixture unit\n"
        (package / "src/dummy.cc").write_bytes(data)
        cache = registry / "cache" / index
        cache.mkdir(parents=True)
        archive = cache / (package.name + ".crate")
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo(package.name + "/src/dummy.cc")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (source / "Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "link-cplusplus"\n'
            'version = "1.0.12"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{checksum}"\n'
        )
        return source, package

    def test_registry_cwd_probe_and_source(self) -> None:
        import json
        from contextlib import contextmanager

        root = Path(self.enterContext(TemporaryDirectory()))
        source, package = self._registry_fixture(root)
        build = root / "build"
        (build / "p25capture").mkdir(parents=True)
        probe = build / "probe.cc"
        probe.write_text("// generated probe\n")

        @contextmanager
        def tool(alias: str):
            yield 123, {"path": alias, "sha256": "a" * 64}

        def runner(
            fd: int, argv: list[str], cwd: Path, env: dict[str, str]
        ) -> tuple[int, bytes, bytes]:
            self.assertEqual(cwd, package)
            if "-MF" in argv:
                Path(argv[argv.index("-MF") + 1]).write_text("o: src/dummy.cc\n")
            return 0, b"", b""

        with (
            patch.dict(p.PROFILE, {"registry_source_root": str(package.parents[1])}),
            patch.object(p, "trusted_tool", tool),
        ):
            config = {"source": str(source), "build": str(build)}
            for argv in (["-E", str(probe)], ["-c", "src/dummy.cc"]):
                p.compiler_capture(config, argv, package, {}, runner)
        row = json.loads((build / "p25capture/1.json").read_bytes())
        self.assertEqual(row["cwd"], str(package))
        self.assertEqual(row["unit"], str(package / "src/dummy.cc"))

    def test_registry_rejects_pax_expansion_and_hidden_tar_tail(self) -> None:
        import gzip
        import hashlib
        import io
        import re
        import tarfile

        for case in ("pax-expansion", "pax-metadata", "sparse", "tail", "no-end"):
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, package = self._registry_fixture(root)
                headers = (
                    {"comment": "x" * 100_000}
                    if case in ("pax-expansion", "pax-metadata")
                    else {"GNU.sparse.unexpected": "1"}
                    if case == "sparse"
                    else {}
                )
                raw = io.BytesIO()
                with tarfile.open(
                    fileobj=raw,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                    pax_headers=headers,
                ) as archive:
                    body = (package / "src/dummy.cc").read_bytes()
                    member = tarfile.TarInfo(package.name + "/src/dummy.cc")
                    member.size = len(body)
                    archive.addfile(member, io.BytesIO(body))
                data = raw.getvalue()
                if case == "tail":
                    # Валидный второй header скрыт после первого end marker.
                    hidden = tarfile.TarInfo("../unsafe")
                    data += hidden.tobuf() + bytes(1024)
                elif case == "no-end":
                    data = data[:1024]
                cached = root / "registry/cache" / package.parent.name
                path = cached / (package.name + ".crate")
                path.write_bytes(gzip.compress(data))
                lock = source / "Cargo.lock"
                lock.write_text(
                    re.sub(
                        r'checksum = "[0-9a-f]{64}"',
                        f'checksum = "{hashlib.sha256(path.read_bytes()).hexdigest()}"',
                        lock.read_text(),
                    )
                )
                with (
                    patch.dict(
                        p.PROFILE,
                        {
                            "registry_source_root": str(package.parents[1]),
                            "registry_unpacked_byte_cap": (
                                16_384 if case == "pax-expansion" else 262_144
                            ),
                        },
                    ),
                    patch.object(
                        p, "MAX_METADATA", 1024 if case == "pax-metadata" else 1_048_576
                    ),
                    self.assertRaises(ValueError),
                ):
                    with p.registry_package(source, package):
                        pass

    def test_registry_tar_bounded_parser_accepts_pax_and_plain_source(self) -> None:
        import gzip
        import io
        import tarfile

        raw = io.BytesIO()
        with tarfile.open(
            fileobj=raw,
            mode="w",
            format=tarfile.PAX_FORMAT,
            pax_headers={"comment": "обычные metadata"},
        ) as archive:
            member = tarfile.TarInfo("source/Cargo.lock")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"lock"))
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                data = gzip.compress(raw.getvalue()) if compressed else raw.getvalue()
                with p._registry_tar(data, gzip_encoded=compressed) as archive:
                    members = list(archive)
                    self.assertEqual([m.name for m in members], ["source/Cargo.lock"])
                    with archive.extractfile(members[0]) as stream:
                        self.assertEqual(stream.read(), b"lock")

    def test_registry_tar_caps_before_high_level_metadata_parser(self) -> None:
        import gzip
        from unittest.mock import Mock

        parser = Mock(side_effect=AssertionError("High-level parser reached"))
        with (
            patch.dict(p.PROFILE, {"registry_unpacked_byte_cap": 4096}),
            patch.object(p.tarfile, "open", parser),
            self.assertRaisesRegex(ValueError, "decoded byte cap"),
        ):
            with p._registry_tar(gzip.compress(bytes(8192))):
                pass
        parser.assert_not_called()

    def test_registry_tar_rejects_recursive_metadata_chain_before_parser(self) -> None:
        import io
        import tarfile
        from unittest.mock import Mock

        raw = io.BytesIO()
        for _ in range(9):
            header = tarfile.TarInfo("metadata")
            header.type = tarfile.XHDTYPE
            raw.write(header.tobuf())
        raw.write(bytes(1024))
        parser = Mock(side_effect=AssertionError("High-level parser reached"))
        with (
            patch.object(p.tarfile, "open", parser),
            self.assertRaisesRegex(ValueError, "metadata chain cap"),
        ):
            with p._registry_tar(raw.getvalue(), gzip_encoded=False):
                pass
        parser.assert_not_called()

    def test_registry_rejects_unselected_unit_before_compiler(self) -> None:
        from unittest.mock import Mock

        root = Path(self.enterContext(TemporaryDirectory()))
        source, package = self._registry_fixture(root)
        build = root / "build"
        (build / "p25capture").mkdir(parents=True)
        config = {"source": str(source), "build": str(build)}
        runner = Mock()
        with (
            patch.dict(p.PROFILE, {"registry_source_root": str(package.parents[1])}),
            patch.object(p, "trusted_tool") as tool,
        ):
            for unit in (
                str(package.with_name("other-1.0.0") / "src/dummy.cc"),
                "src/../../other-1.0.0/dummy.cc",
                "unarchived.cc",
            ):
                with self.subTest(unit=unit), self.assertRaises(ValueError):
                    p.compiler_capture(config, ["-c", unit], package, {}, runner)
            tool.assert_not_called()
            runner.assert_not_called()

    def test_registry_tar_rejects_offset_overrides_before_parser(self) -> None:
        import gzip
        import io
        import tarfile
        from unittest.mock import Mock

        hidden = io.BytesIO()
        for _ in range(400):
            header = tarfile.TarInfo("metadata")
            header.type = tarfile.XHDTYPE
            hidden.write(header.tobuf())
        hidden.write(bytes(1024))
        body = hidden.getvalue()
        for kind in ("pax-size", "directory", "link"):
            with self.subTest(kind=kind):
                raw = io.BytesIO()
                header = tarfile.TarInfo("package/payload")
                header.size = len(body)
                if kind == "pax-size":
                    pax = tarfile.TarInfo("metadata")
                    pax.type = tarfile.XHDTYPE
                    pax.size = 10
                    raw.write(pax.tobuf())
                    raw.write(b"10 size=0\n" + bytes(502))
                else:
                    header.type = (
                        tarfile.DIRTYPE if kind == "directory" else tarfile.SYMTYPE
                    )
                raw.write(header.tobuf())
                raw.write(body)
                raw.write(bytes(1024))
                parser = Mock(side_effect=AssertionError("High-level parser reached"))
                with (
                    patch.object(p.tarfile, "open", parser),
                    self.assertRaisesRegex(
                        ValueError, "size override|nonregular payload"
                    ),
                ):
                    with p._registry_tar(gzip.compress(raw.getvalue())):
                        pass
                parser.assert_not_called()

    def test_registry_rejects_untrusted_inputs_and_mutation(self) -> None:
        for case in (
            "unknown",
            "prefix",
            "traversal",
            "symlink",
            "checksum",
            "member",
            "mutation",
            "lock-mutation",
            "archive-mutation",
        ):
            with self.subTest(case=case), TemporaryDirectory() as temp:
                root = Path(temp)
                source, package = self._registry_fixture(root)
                cwd = package
                if case == "unknown":
                    cwd = package.with_name("unknown-1.0.0")
                elif case == "prefix":
                    cwd = package.with_name(package.name + "-sibling")
                elif case == "traversal":
                    cwd = package / ".." / package.name
                elif case == "symlink":
                    original = package.with_name("original")
                    package.rename(original)
                    package.symlink_to(original, target_is_directory=True)
                elif case == "checksum":
                    archive = (
                        root
                        / "registry/cache"
                        / package.parent.name
                        / (package.name + ".crate")
                    )
                    archive.write_bytes(b"tampered archive")
                elif case == "member":
                    (package / "src/dummy.cc").write_bytes(b"tampered")
                with patch.dict(
                    p.PROFILE, {"registry_source_root": str(package.parents[1])}
                ):
                    with self.assertRaises((ValueError, OSError)):
                        with p.registry_package(source, cwd):
                            if case == "mutation":
                                (package / "src/dummy.cc").write_bytes(b"changed")
                            elif case == "lock-mutation":
                                (source / "Cargo.lock").write_text("changed")
                            elif case == "archive-mutation":
                                archive = (
                                    root
                                    / "registry/cache"
                                    / package.parent.name
                                    / (package.name + ".crate")
                                )
                                archive.write_bytes(b"changed")

    def test_fixed_arch_qt_query_argv_and_receipt(self) -> None:
        import json
        from contextlib import contextmanager
        from unittest.mock import Mock

        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        expected = ["/usr/lib/qt6/bin/qtpaths", "--qt-version"]
        identity = {"path": expected[0], "sha256": "a" * 64}

        @contextmanager
        def fake_tool(alias: str):
            self.assertEqual(alias, expected[0])
            yield 123, identity

        runner = Mock(return_value=(0, b"6.11.2\n", b""))
        env = {"PATH": "/untrusted", "QT_HOST_BINS": "/untrusted"}
        with patch.object(p, "trusted_tool", side_effect=fake_tool) as tool:
            p.prepare(tmp_path, tmp_path / "build", env, runner=runner)
        tool.assert_called_once_with(expected[0])
        runner.assert_called_once_with(123, expected, tmp_path, env)
        receipt = json.loads(
            (tmp_path / "build/p25capture/qt-observed.json").read_bytes()
        )
        self.assertEqual(receipt["query_argv"], expected)
        self.assertEqual(receipt["tool"], identity)

    def test_missing_fixed_qt_tool_never_falls_back(self) -> None:
        from unittest.mock import Mock

        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        runner = Mock()
        with patch.object(
            p, "trusted_tool", side_effect=FileNotFoundError("fixed Qt tool")
        ) as tool:
            with self.assertRaises(FileNotFoundError):
                p.prepare(tmp_path, tmp_path / "build", {}, runner=runner)
        tool.assert_called_once_with("/usr/lib/qt6/bin/qtpaths")
        runner.assert_not_called()
        self.assertFalse((tmp_path / "build/p25capture/qt-observed.json").exists())

    def test_qt_tool_rejects_other_aliases_before_filesystem_access(self) -> None:
        with patch.object(p.Path, "resolve") as resolve:
            for alias in ("qtpaths", "qtpaths6", "/usr/bin/qtpaths6"):
                with self.subTest(alias=alias):
                    with self.assertRaisesRegex(ValueError, "fixed tool"):
                        with p.trusted_tool(alias):
                            self.fail("Недоверенный Qt tool принят")
            resolve.assert_not_called()

    def test_make_escaping(self) -> None:
        self.assertEqual(
            p.dependencies(
                b"obj\\ name.o: src\\ name.cpp /sdk/a\\#b.h \\\n /sdk/a$$b.h\n"
            ),
            ["src name.cpp", "/sdk/a#b.h", "/sdk/a$b.h"],
        )

    def _check_make_rejects_unsupported(self, raw: bytes) -> None:
        with self.assertRaises(ValueError):
            p.dependencies(raw)

    def test_make_rejects_unsupported(self) -> None:
        for raw in [b"o: $(shell bad)", b"o: a\no2: b", b"o: a\\", b"o:"]:
            with self.subTest(raw=raw):
                self._check_make_rejects_unsupported(raw)

    def test_compile_plan_adds_only_dependency_flags(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        argv = ["-I/usr/include", "-c", "a.cpp", "-o", "a.o"]
        observed = p.compile_arguments(argv, tmp_path / "1.d")
        self.assertEqual(observed, [*argv, "-MD", "-MF", str(tmp_path / "1.d")])
        for bad in (
            ["@response"],
            ["-c", "a.cpp", "-MF", "other"],
            ["-c", "a.cpp", "-MMD"],
        ):
            with self.assertRaises(ValueError):
                p.compile_arguments(bad, tmp_path / "1.d")

    def _check_positive_final_metadata(
        self, tmp_path: Path, patches: ExitStack, case: str
    ) -> None:
        import hashlib
        import json
        import os
        from contextlib import contextmanager

        import _p25_capture_producer as producer

        task = tmp_path / "task"
        source, build, sdk, retained = (
            task / "source",
            task / "target",
            tmp_path / "sdk",
            tmp_path / "retained",
        )
        for root in (source, build, sdk, retained):
            root.mkdir(parents=True, exist_ok=True)
        (build / "release").mkdir()
        (build / "release/elf").write_bytes(b"fixture ELF")
        (source / "input.cpp").write_text("// source fixture\n")
        generated = build / "bridge.cxx.cpp"
        generated.write_text(
            "// SPDX-License-Identifier: MIT\n// fixture generated bytes\n"
        )
        header = sdk / "a space.h"
        header.write_text("// SPDX-License-Identifier: LGPL-3.0-only\n")
        for name in ("compiler", "qtpaths"):
            (sdk / name).write_bytes(b"fixture never executed " + name.encode())
        patches.enter_context(patch.dict(p.PROFILE, {"sdk_root": str(sdk)}))
        descriptors = []

        @contextmanager
        def fake_tool(alias: str):
            path = sdk / ("compiler" if alias == p.PROFILE["compiler"] else "qtpaths")
            with path.open("rb") as stream:
                descriptors.append(stream.fileno())
                yield (
                    stream.fileno(),
                    {
                        "path": str(path),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    },
                )

        calls = []

        def fake(
            fd: int, argv: list[str], cwd: Path, env: dict[str, str]
        ) -> tuple[int, bytes, bytes]:
            self.assertTrue(os.fstat(fd))
            calls.append(list(argv))
            if argv == p.PROFILE["qt_query"]:
                return (0, b"6.11.2\n", b"")
            dep = Path(argv[argv.index("-MF") + 1])
            escaped = str(header).replace(" ", "\\ ")
            dep.write_text(
                f"bridge.o: {argv[argv.index('-c') + 1]} {source / 'input.cpp'} {escaped}\n"
            )
            return (0, b"", b"fixture diagnostics")

        patches.enter_context(patch.object(p, "trusted_tool", fake_tool))
        env = {}
        p.prepare(source, build, env, runner=fake)
        self.assertEqual(p.wrapper_config(env)["source"], str(source))
        p.compiler_capture(
            p.wrapper_config(env),
            ["-c", str(generated), "-o", "bridge.o"],
            source,
            env,
            runner=fake,
        )
        if case == "external-unit":
            fixture_source, package = self._registry_fixture(tmp_path / "dependency")
            (source / "Cargo.lock").write_bytes(
                (fixture_source / "Cargo.lock").read_bytes()
            )
            external_unit = package / "src/dummy.cc"
            patches.enter_context(
                patch.dict(p.PROFILE, {"registry_source_root": str(package.parents[1])})
            )
            p.compiler_capture(
                p.wrapper_config(env),
                ["-c", str(external_unit), "-o", "external.o"],
                source,
                env,
                runner=fake,
            )
        if case == "repeat-unit":
            p.compiler_capture(
                p.wrapper_config(env),
                ["-c", str(generated), "-o", "second.o"],
                source,
                env,
                runner=fake,
            )
        if case in ("parent-normalization", "symlink-parent"):
            parent = sdk / "nested"
            parent.mkdir()
            if case == "symlink-parent":
                alias = sdk / "link"
                alias.symlink_to(parent, target_is_directory=True)
                parent = alias
            escaped = f"{parent}/../a space.h".replace(" ", "\\ ")
            (build / "p25capture/0.d").write_text(
                f"o: {generated} {escaped} {source / 'input.cpp'}\n"
            )
        if case == "outside":
            (build / "p25capture/0.d").write_text(
                f"o: {generated} /not-whitelisted/private.h\n"
            )
        if case == "symlink":
            alias = sdk / "alias.h"
            alias.symlink_to(header)
            (build / "p25capture/0.d").write_text(f"o: {generated} {alias}\n")
        if case == "identity":
            (sdk / "compiler").write_bytes(b"changed after compilation")
        if case == "missing-record":
            (build / "p25capture/count").write_text("2")
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)
        frozen = {
            "source": {"commit": "a" * 40, "tree": "b" * 40},
            "archive_sha256": "c" * 64,
            "final_profile": {"spec": dict(p.PROFILE)},
        }
        commands = [{"argv": ["slot", "cargo", "build"], "cwd": str(source), "exit": 0}]
        if case in (
            "outside",
            "symlink",
            "identity",
            "missing-record",
            "symlink-parent",
        ):
            with self.assertRaises((ValueError, OSError)):
                producer.retain(
                    source,
                    build,
                    retained,
                    frozen,
                    commands,
                    ["elf"],
                    "target",
                    final_profile=True,
                )
            self.assertFalse((retained / "build-capture-manifest.json").exists())
            return
        result = producer.retain(
            source,
            build,
            retained,
            frozen,
            commands,
            ["elf"],
            "target",
            final_profile=True,
        )
        self.assertEqual(
            len(calls), 3 if case in ("external-unit", "repeat-unit") else 2
        )
        self.assertEqual(
            result["positive_metadata"]["compiled_units"],
            2 if case in ("external-unit", "repeat-unit") else 1,
        )
        self.assertEqual(result["positive_metadata"]["qt_version"], "6.11.2")
        self.assertEqual(result["status"], "MISSING")
        report = json.loads((retained / "build-capture-report.json").read_bytes())
        self.assertTrue(report["qt_binding"]["query_tool"]["sha256"])
        self.assertEqual(report["compile_units"][0]["argv"], calls[1])
        self.assertEqual(
            len(report["compile_units"][0]["normalized_depfile"]["dependencies"]), 3
        )
        self.assertEqual(
            report["unbound_generated_sources"][0]["text"], generated.read_text()
        )
        self.assertIs(report["unbound_generated_sources"][0]["generation_record"], None)
        self.assertEqual(
            report["headers"][0]["file"]["sha256"],
            hashlib.sha256(header.read_bytes()).hexdigest(),
        )
        self.assertTrue(report["source"]["tracked_inputs"])
        self.assertIs(report["final_linux_acceptance"], False)
        if case == "external-unit":
            self.assertTrue(any((row["kind"] == "sdk-unit" for row in report["files"])))
        observed = json.loads((retained / "build-cxx-observed.json").read_bytes())
        self.assertTrue(observed["records"][0]["compiler"]["sha256"])
        self.assertEqual(observed["config"]["source"], str(source))
        self.assertEqual(observed["config_sha256"], env["YONIK_P25_CONFIG_SHA256"])
        self.assertTrue(all((row["kind"] == "elf" for row in result["elfs"])))
        self.assertEqual(
            result["positive_metadata"]["observed_sha256"],
            hashlib.sha256(
                (retained / "build-cxx-observed.json").read_bytes()
            ).hexdigest(),
        )
        self.assertTrue(
            all(
                (
                    row["kind"] != "header"
                    or row["path"] == observed["input_origins"][str(header)]
                    for row in report["files"]
                )
            )
        )

    def test_positive_final_metadata(self) -> None:
        for case in [
            "positive",
            "outside",
            "symlink",
            "identity",
            "missing-record",
            "external-unit",
            "repeat-unit",
            "parent-normalization",
            "symlink-parent",
        ]:
            with (
                self.subTest(case=case),
                TemporaryDirectory() as temporary,
                ExitStack() as patches,
            ):
                tmp_path = Path(temporary)
                self._check_positive_final_metadata(tmp_path, patches, case)

    def test_failed_compiler_not_normalized(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        patches = self.enterContext(ExitStack())
        import json
        from contextlib import contextmanager

        source, build = (tmp_path / "source", tmp_path / "target")
        source.mkdir()
        (build / "p25capture").mkdir(parents=True)

        @contextmanager
        def fake_tool(alias: str):
            yield (100, {"path": "/fixture/compiler", "sha256": "a" * 64})

        patches.enter_context(patch.object(p, "trusted_tool", fake_tool))
        code, _, _ = p.compiler_capture(
            {"source": str(source), "build": str(build)},
            ["-c", "a.cpp"],
            source,
            {},
            runner=lambda *args: (1, b"", b"error"),
        )
        self.assertEqual(code, 1)
        row = json.loads((build / "p25capture/0.json").read_bytes())
        self.assertTrue(row["depfile"] is None and row["unit"] is None)

    def test_wrapper_rejects_config_pin_and_symlink(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        patches = self.enterContext(ExitStack())
        import hashlib
        import json

        source, build, sdk = (tmp_path / key for key in ("source", "build", "sdk"))
        for root in (source, build / "p25capture", sdk):
            root.mkdir(parents=True)
        patches.enter_context(patch.dict(p.PROFILE, {"sdk_root": str(sdk)}))
        config = build / "p25capture/config.json"
        config.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "source": str(source),
                    "build": str(build),
                    "sdk": str(sdk),
                }
            )
        )
        env = {"YONIK_P25_CONFIG": str(config), "YONIK_P25_CONFIG_SHA256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "pin"):
            p.wrapper_config(env)
        env["YONIK_P25_CONFIG_SHA256"] = hashlib.sha256(config.read_bytes()).hexdigest()
        self.assertEqual(p.wrapper_config(env)["schema"], 1)
        alias = tmp_path / "alias"
        alias.symlink_to(build, target_is_directory=True)
        env["YONIK_P25_CONFIG"] = str(alias / "p25capture/config.json")
        with self.assertRaises(OSError):
            p.wrapper_config(env)

    def test_reservation_cap_and_counter_symlink(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        build = tmp_path / "build"
        capture = build / "p25capture"
        capture.mkdir(parents=True)
        (capture / "count").write_text(str(p.MAX_FILES))
        with self.assertRaisesRegex(ValueError, "cap"):
            p._reserve(build)
        other = tmp_path / "other"
        other.mkdir()
        (other / "p25capture").symlink_to(capture, target_is_directory=True)
        with self.assertRaises(OSError):
            p._reserve(other)

    def test_fixed_tool_fd_closed_and_hashed(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        patches = self.enterContext(ExitStack())
        import hashlib
        import os

        sdk = tmp_path / "sdk"
        sdk.mkdir()
        binary = sdk / "compiler"
        binary.write_bytes(b"not executable, fixture only")
        alias = sdk / "fixed-alias"
        alias.symlink_to(binary)
        patches.enter_context(patch.dict(p.PROFILE, {"sdk_root": str(sdk)}))
        patches.enter_context(patch.dict(p.PROFILE, {"compiler": str(alias)}))
        with p.trusted_tool(str(alias)) as (fd, identity):
            self.assertEqual(
                identity["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest()
            )
            self.assertEqual(identity["path"], str(binary))
            self.assertTrue(os.fstat(fd))
        with self.assertRaises(OSError):
            os.fstat(fd)
        with self.assertRaisesRegex(ValueError, "fixed"):
            with p.trusted_tool("/arbitrary/command"):
                pass

    def test_query_failure_not_promoted(self) -> None:
        tmp_path = Path(self.enterContext(TemporaryDirectory()))
        patches = self.enterContext(ExitStack())
        from contextlib import contextmanager

        source = tmp_path / "source"
        source.mkdir()

        @contextmanager
        def fake_tool(alias: str):
            yield (100, {"path": "/fixture/qt", "sha256": "a" * 64})

        patches.enter_context(patch.object(p, "trusted_tool", fake_tool))
        with self.assertRaisesRegex(ValueError, "Qt query"):
            p.prepare(
                source,
                tmp_path / "build",
                {},
                runner=lambda *args: (1, b"6.11.2\n", b"failed"),
            )
        self.assertFalse((tmp_path / "build/p25capture/qt-observed.json").exists())

    def _check_executor_bounds_and_reaps_without_execution(
        self, tmp_path: Path, patches: ExitStack, failure: str | None
    ) -> None:
        from types import SimpleNamespace

        class Stream:
            def __init__(self, fd: int) -> None:
                self.fd = fd

            def fileno(self) -> int:
                return self.fd

        class Process:
            pid = 123456
            stdout = Stream(100)
            stderr = Stream(101)
            waits = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def wait(self, timeout: float | None = None) -> int:
                self.waits += 1
                return 0

        class Selector:
            def __init__(self) -> None:
                self.keys = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def register(self, stream: Stream, events: int, index: int) -> None:
                self.keys[stream.fd] = SimpleNamespace(fileobj=stream, data=index)

            def unregister(self, stream: Stream) -> None:
                del self.keys[stream.fd]

            def get_map(self) -> dict:
                return self.keys

            def select(self, timeout: float) -> list:
                return [(value, 1) for value in list(self.keys.values())]

        child = Process()
        launched = []
        killed = []

        def popen(argv: list[str], **kwargs):
            launched.append(kwargs)
            return child

        patches.enter_context(patch.object(p.subprocess, "Popen", popen))
        patches.enter_context(patch.object(p.selectors, "DefaultSelector", Selector))
        patches.enter_context(patch.object(p.os, "set_blocking", lambda *args: None))
        patches.enter_context(
            patch.object(p.os, "killpg", lambda pid, sig: killed.append(pid))
        )
        patches.enter_context(
            patch.object(
                p.os, "read", lambda *args: b"xxxx" if failure == "cap" else b""
            )
        )
        patches.enter_context(patch.dict(p.PROFILE, {"stream_cap": 3}))
        clock = iter([0, 301]) if failure == "deadline" else None
        patches.enter_context(
            patch.object(p.time, "monotonic", lambda: next(clock) if clock else 0)
        )
        if failure:
            with self.assertRaisesRegex(ValueError, "cap|deadline"):
                p.execute(999, ["fixed-tool"], tmp_path, {})
        else:
            self.assertEqual(
                p.execute(999, ["fixed-tool"], tmp_path, {}), (0, b"", b"")
            )
        self.assertEqual(launched[0]["executable"], "/proc/self/fd/999")
        self.assertEqual(launched[0]["pass_fds"], (999,))
        self.assertIs(launched[0]["start_new_session"], True)
        self.assertNotIn("shell", launched[0])
        self.assertTrue(killed == [child.pid] and child.waits >= 1)

    def test_executor_bounds_and_reaps_without_execution(self) -> None:
        for failure in ["cap", "deadline", None]:
            with (
                self.subTest(failure=failure),
                TemporaryDirectory() as temporary,
                ExitStack() as patches,
            ):
                tmp_path = Path(temporary)
                self._check_executor_bounds_and_reaps_without_execution(
                    tmp_path, patches, failure
                )


class ClosedProbeAndAliasTests(unittest.TestCase):
    """SYNTHETIC reconstruction; никогда не является capture03 receipt."""

    evidence = Path(
        "/home/myrs/projects/yonik/local/orchestration/evidence/n5-next-capture-preflight/capture-03-raw"
    )

    @unittest.skipUnless(
        evidence.exists(), "Локальный diagnostic checkpoint отсутствует"
    )
    def test_all_337_retained_argv_with_injected_runner(self) -> None:
        import hashlib
        import json
        import tarfile
        from contextlib import contextmanager

        checkpoint = json.loads((self.evidence / "checkpoint.json").read_bytes())
        crate = (self.evidence / "cc-1.11.1.crate").read_bytes()
        self.assertEqual(
            hashlib.sha256(crate).hexdigest(),
            "4ff2a8126fff0f8c839080d619675a585e61720bb12d2baceae45769fd66f155",
        )
        with tarfile.open(self.evidence / "cc-1.11.1.crate") as archive:
            family = archive.extractfile(
                "cc-1.11.1/src/detect_compiler_family.c"
            ).read()
        root = Path(self.enterContext(TemporaryDirectory()))
        build, source = root / "build", root / "source"
        source.mkdir()
        (build / "p25capture").mkdir(parents=True)

        @contextmanager
        def tool(alias: str):
            yield 1, {"path": alias, "sha256": "a" * 64}

        rows = []
        for item in checkpoint["files"]:
            if not item["origin"].endswith(".json"):
                continue
            raw = (self.evidence / item["file"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
            value = json.loads(raw)
            if "original_argv" in value:
                rows.append(value)
        self.assertEqual(len(rows), 337)
        counts = {}
        for index, original in enumerate(rows):
            argv = [
                arg.replace(checkpoint["original_build"], str(build))
                for arg in original["original_argv"]
            ]
            purpose, path = p.probe_shape(argv, build)
            if path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(
                    family if purpose == "family-preprocess" else p.FLAG_BODY
                )
            counts[purpose] = counts.get(purpose, 0) + 1

            def runner(
                fd: int, command: list[str], cwd: Path, env: dict[str, str]
            ) -> tuple[int, bytes, bytes]:
                if purpose in {"family-query", "family-preprocess", "flag-support"}:
                    self.assertEqual(command[1:], argv)
                return original["exit"], b"", b""

            with patch.object(p, "trusted_tool", tool):
                code, _, _ = p.compiler_capture(
                    {"build": str(build), "source": str(source), "sdk": "/usr"},
                    argv,
                    source,
                    {},
                    runner,
                )
            row = json.loads((build / f"p25capture/{index}.json").read_bytes())
            self.assertEqual(code, original["exit"])
            probe = p.validate_purpose(row, build)
            if probe:
                self.assertIsNone(row["unit"])
                self.assertIsNone(row["depfile"])
            if path:
                Path(path).unlink()
                self.assertTrue(p.validate_purpose(row, build))
        self.assertEqual(counts["family-query"], 9)
        self.assertEqual(counts["family-preprocess"], 9)
        self.assertEqual(counts["flag-support"], 28)

    def test_closed_proof_negatives(self) -> None:
        import copy
        import hashlib

        build = Path("/synthetic/build")
        src = build / ("release/build/cxx-qt-" + "a" * 16) / "out/flag_check.cpp"
        argv = [
            *p.FLAG_PREFIX,
            "/bigobj",
            "-o",
            str(src.with_suffix("")),
            "-c",
            str(src),
        ]
        row = {
            "schema": 2,
            "original_argv": argv,
            "purpose": "flag-support",
            "probe": {
                "source": str(src),
                "bytes_hex": p.FLAG_BODY.hex(),
                "sha256": hashlib.sha256(p.FLAG_BODY).hexdigest(),
            },
            "exit": 1,
            "unit": None,
            "depfile": None,
        }
        row["argv"] = [p.PROFILE["compiler"], *argv]
        self.assertTrue(p.validate_purpose(row, build))
        self.assertTrue(p.validate_purpose(dict(row, exit=0), build))
        for field, value in [
            ("schema", 3),
            ("schema", True),
            ("exit", True),
            ("exit", 2),
            ("purpose", "compile"),
            ("unit", str(src)),
            ("depfile", "x"),
        ]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                p.validate_purpose(dict(row, **{field: value}), build)
        for extra in ["-include", "-fplugin=x", "-I/private"]:
            bad = dict(row, original_argv=[*argv, extra])
            with self.assertRaises(ValueError):
                p.validate_purpose(bad, build)
        bad = copy.deepcopy(row)
        bad["probe"]["bytes_hex"] = b"production".hex()
        with self.assertRaises(ValueError):
            p.validate_purpose(bad, build)
        bad = dict(row, schema=1)
        with self.assertRaises(ValueError):
            p.validate_purpose(bad, build)
        with self.assertRaises(ValueError):
            p.validate_purpose({"schema": 1, "exit": 1}, build)

    @unittest.skipUnless(
        evidence.exists(), "Локальный diagnostic checkpoint отсутствует"
    )
    def test_actual_11_alias_shapes_and_retained_only_mapping(self) -> None:
        import hashlib
        import json

        root = Path(self.enterContext(TemporaryDirectory()))
        build = root / "build"
        build.mkdir()
        checkpoint = json.loads((self.evidence / "checkpoint.json").read_bytes())
        observations = json.loads(
            (self.evidence / "alias-observation.json").read_bytes()
        )["aliases"]
        self.assertEqual(len(observations), 11)
        expected = {}
        for origin, item in observations.items():
            canonical = Path(
                item["canonical"].replace(checkpoint["original_build"], str(build))
            )
            canonical.parent.mkdir(parents=True, exist_ok=True)
            raw = (self.evidence / item["retained_file"]).read_bytes()
            canonical.write_bytes(raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
            for link in item["links"]:
                path = Path(
                    link["path"].replace(checkpoint["original_build"], str(build))
                )
                target = link["target"].replace(
                    checkpoint["original_build"], str(build)
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.is_symlink():
                    path.symlink_to(target)
            expected[origin.replace(checkpoint["original_build"], str(build))] = str(
                canonical
            )
        metadata = {}
        with ExitStack() as stack:
            for alias, expected_canonical in expected.items():
                canonical, links = p.alias_target(Path(alias), build, stack)
                self.assertEqual(str(canonical), expected_canonical)
                metadata[alias] = {
                    "canonical": str(canonical),
                    "links": links,
                    "sha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
                }
        # Pure replay не открывает никакие paths.
        with patch("os.open", side_effect=AssertionError("offline I/O")):
            self.assertEqual(p.validate_aliases(metadata, build), expected)
        observed = {"schema": 2, "config": {"build": str(build)}, "aliases": metadata}
        whitelist = [
            {
                "root": "build",
                "path": Path(value["canonical"]).relative_to(build).as_posix(),
                "kind": "generated",
                "sha256": value["sha256"],
            }
            for value in metadata.values()
        ]
        with patch("os.open", side_effect=AssertionError("offline I/O")):
            self.assertEqual(
                p.validate_observed_extensions(observed, whitelist), expected
            )
            with self.assertRaises(ValueError):
                p.validate_observed_extensions(observed, [])
        for bad in [
            build / "private.h",
            build
            / "release/build/unknown-aaaaaaaaaaaaaaaa/out/cxxqtbuild/include/cxx-qt/a.h",
            build
            / "release/build/cxx-qt-aaaaaaaaaaaaaaaa/out/cxxqtbuild/include/cxx-qt/a.cpp",
        ]:
            with ExitStack() as stack, self.assertRaises(ValueError):
                p.alias_target(bad, build, stack)

    def test_alias_escape_cycle_and_mutation(self) -> None:
        root = Path(self.enterContext(TemporaryDirectory()))
        build = root / "build"
        include = build / "release/build/cxx-qt-aaaaaaaaaaaaaaaa/out/cxxqtbuild/include"
        include.mkdir(parents=True)
        alias = include / "cxx-qt"
        alias.symlink_to("/private")
        with ExitStack() as stack, self.assertRaises(ValueError):
            p.alias_target(alias / "x.h", build, stack)
        alias.unlink()
        alias.symlink_to(alias)
        with ExitStack() as stack, self.assertRaises(ValueError):
            p.alias_target(alias / "x.h", build, stack)
        alias.unlink()
        alias.mkdir()
        header = alias / "x.h"
        header.write_bytes(b"header")
        stack = ExitStack()
        p.alias_target(header, build, stack)
        header.write_bytes(b"mutation")
        with self.assertRaises(ValueError):
            stack.close()

    def test_probe_source_mutation_during_runner_refused(self) -> None:
        from contextlib import contextmanager

        root = Path(self.enterContext(TemporaryDirectory()))
        source, build = root / "source", root / "build"
        source.mkdir()
        (build / "p25capture").mkdir(parents=True)
        path = build / "release/build/cxx-qt-aaaaaaaaaaaaaaaa/out/flag_check.cpp"
        path.parent.mkdir(parents=True)
        path.write_bytes(p.FLAG_BODY)
        argv = [
            *p.FLAG_PREFIX,
            "/bigobj",
            "-o",
            str(path.with_suffix("")),
            "-c",
            str(path),
        ]

        @contextmanager
        def tool(alias: str):
            yield 1, {"path": alias, "sha256": "a" * 64}

        def runner(
            fd: int, command: list[str], cwd: Path, env: dict[str, str]
        ) -> tuple[int, bytes, bytes]:
            path.write_bytes(b"replacement")
            return 1, b"", b""

        with patch.object(p, "trusted_tool", tool), self.assertRaises(ValueError):
            p.compiler_capture(
                {"build": str(build), "source": str(source), "sdk": "/usr"},
                argv,
                source,
                {},
                runner,
            )

    def test_alias_ancestor_replacement_refused(self) -> None:
        root = Path(self.enterContext(TemporaryDirectory()))
        build = root / "build"
        path = (
            build
            / "release/build/cxx-qt-aaaaaaaaaaaaaaaa/out/cxxqtbuild/include/cxx-qt/x.h"
        )
        path.parent.mkdir(parents=True)
        path.write_bytes(b"header")
        stack = ExitStack()
        p.alias_target(path, build, stack)
        parent = path.parent
        parent.rename(parent.with_name("old"))
        parent.mkdir()
        (parent / "x.h").write_bytes(b"header")
        with self.assertRaises(ValueError):
            stack.close()
