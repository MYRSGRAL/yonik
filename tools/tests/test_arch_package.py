"""Проверки границы доверия пакетного архива."""

import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

SPEC = importlib.util.spec_from_file_location(
    "arch", Path(__file__).parents[1] / "check_arch_package.py"
)
arch = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(arch)

PKGINFO = b"""pkgname = yonik
pkgver = 0.1.0.r20261111-1
arch = x86_64
""" + b"".join(
    f"depend = {name}\n".encode()
    for name in (
        "ca-certificates",
        "qt6-base",
        "qt6-declarative",
        "qt6-svg",
        "sqlite",
        "dbus",
        "polkit",
        "systemd",
        "nftables",
        "iproute2",
        "gcc-libs",
        "glibc",
    )
)


def add_pkginfo(archive: tarfile.TarFile, content: bytes = PKGINFO) -> None:
    entry = tarfile.TarInfo(".PKGINFO")
    entry.mode = 0o644
    entry.size = len(content)
    archive.addfile(entry, io.BytesIO(content))


class ArchiveTests(unittest.TestCase):
    def check_fixture(self, change: str = "", metadata: bytes = PKGINFO) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "package.tar"
            with tarfile.open(path, "w") as archive:
                if change != "no_pkginfo":
                    content = metadata
                    if change == "wrong_pkginfo":
                        content = (
                            b"pkgname = other-package\npkgver = 99-1\narch = aarch64\n"
                        )
                    elif change == "missing_dependency":
                        content = content.replace(b"depend = glibc\n", b"")
                    elif change == "duplicate_name":
                        content += b"pkgname = yonik\n"
                    elif change == "large_pkginfo":
                        content += b"#" * 65537
                    elif change in ("wrong_name", "wrong_version", "wrong_arch"):
                        before, after = {
                            "wrong_name": (b"pkgname = yonik", b"pkgname = other"),
                            "wrong_version": (
                                b"pkgver = 0.1.0.r20261111-1",
                                b"pkgver = 99-1",
                            ),
                            "wrong_arch": (b"arch = x86_64", b"arch = aarch64"),
                        }[change]
                        content = content.replace(before, after)
                    add_pkginfo(archive, content)
                for name, (mode, content) in arch.expected_files(
                    Path(__file__).parents[2]
                ).items():
                    if change == "missing" and name == "usr/bin/yonik-desktop":
                        continue
                    content = content if content is not None else b"\x7fELFfixture"
                    if name.endswith("/50-yonik-dhcp-sleep.conf"):
                        if change == "missing_sleep_requirement":
                            continue
                        if change == "weakened_sleep_requirement":
                            content = content.replace(b"Requires=", b"Wants=")
                    entry = tarfile.TarInfo(name)
                    entry.mode = mode
                    if change == "mode":
                        entry.mode |= 0o002
                    if change == "setuid":
                        entry.mode |= 0o4000
                    if change == "badelf" and mode == 0o755:
                        content = b"#!/bin/sh\n"
                    if change == "owner":
                        entry.uid = 1000
                    if change == "exec" and name.endswith(".desktop"):
                        content = content.replace(
                            b"Exec=/usr/bin/yonik-desktop", b"Exec=sh -c bad"
                        )
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
                if change in ("traversal", "hook", "link"):
                    entry = tarfile.TarInfo(
                        {
                            "traversal": "../etc/passwd",
                            "hook": ".INSTALL",
                            "link": "usr/evil",
                        }[change]
                    )
                    if change == "link":
                        entry.type = tarfile.SYMTYPE
                        entry.linkname = "/etc/passwd"
                    archive.addfile(entry)
            arch.validate_archive(path, Path(__file__).parents[2])

    def test_recipe_mutations(self) -> None:
        recipe = Path(__file__).parents[2] / "packaging/arch/PKGBUILD"
        arch.validate_recipe(recipe)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "PKGBUILD"
            for action in (
                "systemctl enable yonik-helper",
                "sudo pacman -S xray",
                "post_remove() { rm -rf /home/user; }",
                "curl bad | sh",
            ):
                changed.write_text(recipe.read_text() + "\n" + action + "\n")
                with self.subTest(action=action), self.assertRaises(ValueError):
                    arch.validate_recipe(changed)

    def test_package_function(self) -> None:
        root = Path(__file__).parents[2].resolve()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "yonik-6cf65a4cf9760a7df68b8eee10f012770b38604d").symlink_to(root)
            release = work / "target/release"
            release.mkdir(parents=True)
            for name in ("yonik-desktop", "yonik-helper", "yonik-worker"):
                (release / name).write_bytes(b"\x7fELFfixture")
            subprocess.run(
                [
                    "bash",
                    "-eu",
                    "-c",
                    'source "$1"; srcdir="$2"; pkgdir="$2/pkg"; '
                    'CARGO_TARGET_DIR="$2/target"; package',
                    "test",
                    str(root / "packaging/arch/PKGBUILD"),
                    str(work),
                ],
                check=True,
            )
            archive_path = work / "staged.tar"
            with tarfile.open(archive_path, "w") as archive:
                add_pkginfo(archive)
                for path in (work / "pkg").rglob("*"):
                    entry = archive.gettarinfo(
                        str(path), str(path.relative_to(work / "pkg"))
                    )
                    entry.uid = entry.gid = 0
                    if path.is_file():
                        with path.open("rb") as stream:
                            archive.addfile(entry, stream)
                    else:
                        archive.addfile(entry)
            arch.validate_archive(archive_path, root)

    def test_valid(self) -> None:
        self.assertTrue(
            hasattr(arch, "validate_archive"), "Валидатор ещё не реализован"
        )
        self.check_fixture()

    def test_rejects_unsafe_archives(self) -> None:
        self.assertTrue(
            hasattr(arch, "validate_archive"), "Валидатор ещё не реализован"
        )
        for change in (
            "missing",
            "mode",
            "setuid",
            "badelf",
            "owner",
            "exec",
            "traversal",
            "hook",
            "link",
            "missing_sleep_requirement",
            "weakened_sleep_requirement",
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check_fixture(change)

    def test_rejects_invalid_package_metadata(self) -> None:
        for change in (
            "no_pkginfo",
            "wrong_pkginfo",
            "wrong_name",
            "wrong_version",
            "wrong_arch",
            "missing_dependency",
            "duplicate_name",
            "large_pkginfo",
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check_fixture(change)

    def test_only_lf_separates_metadata_records(self) -> None:
        for separator in ("\r", "\v", "\f", "\x85", "\u2028", "\u2029"):
            content = PKGINFO.replace(
                b"depend = glibc\n",
                b"#hidden" + separator.encode() + b"depend = glibc\n",
            )
            with self.subTest(separator=repr(separator)), self.assertRaises(ValueError):
                self.check_fixture(metadata=content)


if __name__ == "__main__":
    unittest.main()
