#!/usr/bin/env python3
"""Проверить архив без распаковки и исполнения пакетных hooks (tar или .zst)."""

import argparse
import hashlib
import json
import shlex
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

MAX_PKGINFO = 64 * 1024


def validate_pkginfo(content: bytes, root: Path) -> None:
    """Сверяет metadata с уже проверенным seal рецептом, не исполняя shell."""
    if len(content) > MAX_PKGINFO:
        raise ValueError("Превышен лимит .PKGINFO")
    recipe = root / "packaging/arch/PKGBUILD"
    validate_recipe(recipe)
    fields = {}
    for line in recipe.read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"pkgname", "pkgver", "pkgrel", "arch", "depends"}:
            fields[key] = shlex.split(value.strip("()"))
    expected = {
        "pkgname": fields["pkgname"],
        "pkgver": [fields["pkgver"][0] + "-" + fields["pkgrel"][0]],
        "arch": fields["arch"],
        "depend": fields["depends"],
    }
    actual: dict[str, list[str]] = {}
    # libalpm разделяет записи только LF, не Unicode separators/VT/FF.
    for line in content.decode("utf-8").split("\n"):
        if not line.strip() or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        if not separator or not key or not value or any(ord(c) < 32 for c in line):
            raise ValueError("Некорректная строка .PKGINFO")
        if key in expected:
            actual.setdefault(key, []).append(value)
    if any(
        sorted(actual.get(key, [])) != sorted(value) for key, value in expected.items()
    ):
        raise ValueError(".PKGINFO не соответствует рецепту")


DESKTOP = """[Desktop Entry]
Type=Application
Name=yonik
Comment=Управление прокси-подключениями
Exec=/usr/bin/yonik-desktop
Icon=cloud.highpriority.yonik
Terminal=false
Categories=Network;
""".encode()


def expected_files(root: Path) -> dict[str, tuple[int, bytes | None]]:
    files = {
        name: (0o755, None)
        for name in (
            "usr/bin/yonik-desktop",
            "usr/lib/yonik/yonik-helper",
            "usr/lib/yonik/yonik-worker",
        )
    }
    for source, destination in (
        ("systemd", "usr/lib/systemd/system"),
        ("sysusers", "usr/lib/sysusers.d"),
        ("polkit", "usr/share/polkit-1/actions"),
        ("dbus", "usr/share/dbus-1"),
    ):
        source_root = root / "packaging" / source
        paths = source_root.rglob("*") if source == "systemd" else source_root.iterdir()
        for path in paths:
            if source == "systemd" and path.is_dir():
                continue
            parent = destination
            if source == "dbus":
                parent += "/system.d" if path.suffix == ".conf" else "/system-services"
            files[f"{parent}/{path.relative_to(source_root).as_posix()}"] = (
                0o644,
                path.read_bytes(),
            )
    files["usr/share/icons/hicolor/scalable/apps/cloud.highpriority.yonik.svg"] = (
        0o644,
        (root / "crates/yonik-desktop/assets/yonik.svg").read_bytes(),
    )
    files["usr/share/applications/cloud.highpriority.yonik.desktop"] = (0o644, DESKTOP)
    from compile_notices import collect

    entries, texts = collect(root)
    prefix = "usr/share/licenses/yonik/"
    for digest, data in texts.items():
        files[prefix + digest] = (0o644, data)
    files[prefix + "index.json"] = (
        0o644,
        json.dumps(entries, ensure_ascii=False).encode("utf-8"),
    )
    for name, source in {
        "inventory.json": "packaging/licenses/linux-inventory.json",
        "go-sources.json": "packaging/licenses/composition/go-sources.json",
        "SCOPE.md": "packaging/licenses/composition/P25-SCOPE.md",
        "SOURCE-OBLIGATIONS.md": "packaging/licenses/SOURCE-OBLIGATIONS.md",
        "LICENSE": "LICENSE",
    }.items():
        files[prefix + name] = (0o644, (root / source).read_bytes())
    return files


def validate_archive(
    path: Path, root: Path, *, bound_files: dict[str, tuple[int, str]] | None = None
) -> None:
    expected = expected_files(root)
    bound_files = bound_files or {}
    if expected.keys() & bound_files.keys():
        raise ValueError("Binding не может заменить frozen metadata")
    expected.update({name: (mode, None) for name, (mode, _) in bound_files.items()})
    seen = set()
    # zstd декодирует архив makepkg без дополнительного Python-модуля.
    process = None
    if path.suffix == ".zst":
        process = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE)
    try:
        with (
            tarfile.open(fileobj=process.stdout, mode="r|")
            if process
            else tarfile.open(path) as archive
        ):
            for entry in archive:
                name = entry.name.removeprefix("./").rstrip("/")
                if (
                    name in seen
                    or ".." in PurePosixPath(name).parts
                    or name.startswith("/")
                ):
                    raise ValueError(f"Недопустимый путь: {name}")
                seen.add(name)
                if len(seen) > len(expected) + 128 or entry.size > 512 * 1024 * 1024:
                    raise ValueError("Превышен лимит пакетного архива")
                if entry.uid != 0 or entry.gid != 0 or entry.mode & 0o7022:
                    raise ValueError(f"Небезопасные права: {name}")
                if entry.isdir():
                    if entry.mode != 0o755:
                        raise ValueError(f"Неверные права каталога: {name}")
                    if not any(key.startswith(name + "/") for key in expected):
                        raise ValueError(f"Лишний каталог: {name}")
                    continue
                if not entry.isfile():
                    raise ValueError(f"Ссылка/специальный файл: {name}")
                if name == ".PKGINFO":
                    if entry.size > MAX_PKGINFO or entry.mode != 0o644:
                        raise ValueError("Неверный размер/mode .PKGINFO")
                    stream = archive.extractfile(entry)
                    assert stream is not None
                    validate_pkginfo(stream.read(MAX_PKGINFO + 1), root)
                    continue
                if name in (".BUILDINFO", ".MTREE"):
                    continue
                if name not in expected:
                    raise ValueError(f"Лишний файл/hook: {name}")
                mode, content = expected[name]
                if entry.mode != mode:
                    raise ValueError(f"Неверный mode: {name}")
                stream = archive.extractfile(entry)
                assert stream is not None
                if name in bound_files:
                    if (
                        hashlib.file_digest(stream, "sha256").hexdigest()
                        != bound_files[name][1]
                    ):
                        raise ValueError(f"Подменён bound payload: {name}")
                elif mode == 0o755:
                    if stream.read(4) != b"\x7fELF":
                        raise ValueError(f"Ожидался ELF: {name}")
                elif content is not None and (
                    entry.size != len(content)
                    or stream.read(len(content) + 1) != content
                ):
                    raise ValueError(f"Подменены metadata: {name}")
        if ".PKGINFO" not in seen:
            raise ValueError("Отсутствует .PKGINFO")
        if not expected.keys() <= seen:
            raise ValueError(f"Отсутствуют файлы: {expected.keys() - seen}")
    finally:
        if process:
            process.stdout.close()
            if process.wait() != 0:
                raise ValueError("Ошибка декомпрессии")


def validate_recipe(path: Path) -> None:
    """Fail-closed seal: любое изменение исполняемого shell требует нового review.

    Не пытаемся распознавать произвольный Bash через blacklist: подстановки,
    функции и aliases делают такой анализ ненадёжным. Hash фиксирует целиком
    рецепт без hooks, автозапуска и сетевой установки engine.
    """
    approved = {
        "07fb40b269f664ce2b1a73de26cf630ba1f7bcc4e78a1bffa171b4ae25516414",
        "3d58f0fd4765d3d93cd27f84ccd2d4cd14a876fcb45aa7d5db89dafe9aa47bf4",
    }
    if hashlib.sha256(path.read_bytes()).hexdigest() not in approved:
        raise ValueError(
            "Изменён рецепт: требуется независимая проверка и обновление seal"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, nargs="?")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    validate_recipe(root / "packaging/arch/PKGBUILD")
    if args.archive:
        validate_archive(args.archive, root)


if __name__ == "__main__":
    main()
