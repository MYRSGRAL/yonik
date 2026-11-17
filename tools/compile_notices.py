"""Собирает ограниченные доверенные notices для qrc и Linux payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from xml.sax.saxutils import escape

from check_linux_notices import read_bounded

MAX_ENTRIES = 512
MAX_TOTAL = 16 * 1024 * 1024


def collect(root: Path) -> tuple[list[dict], dict[str, bytes]]:
    base = root / "packaging/licenses"
    inventory = json.loads(read_bounded(base / "linux-inventory.json", root))
    go = json.loads(read_bounded(base / "composition/go-sources.json", root))
    entries: list[dict] = []
    texts: dict[str, bytes] = {}
    total_bytes = 0

    def add(
        name: str, version: str, scope: str, refs: Iterable[tuple[str, Path]]
    ) -> None:
        nonlocal total_bytes
        if len(entries) >= MAX_ENTRIES:
            raise ValueError("Превышен предел записей notices")
        hashes = []
        for digest, path in refs:
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Некорректный hash notices")
            data = read_bounded(path, root)
            if hashlib.sha256(data).hexdigest() != digest or not data.strip():
                raise ValueError("Hash notices не совпал или текст пуст")
            data.decode("utf-8")
            if digest not in texts:
                total_bytes += len(data)
                if total_bytes > MAX_TOTAL:
                    raise ValueError("Превышен предел объёма notices")
                texts[digest] = data
            hashes.append(digest)
        entries.append(dict(name=name, version=version, scope=scope, hashes=hashes))

    def content_paths(refs: list[dict], folder: Path) -> Iterable[tuple[str, Path]]:
        return ((ref["sha256"], folder / ref["sha256"]) for ref in refs)

    for package in inventory["packages"]:
        add(
            package["name"],
            package["version"],
            "Rust",
            content_paths(
                package["license_files"] + package["notice_files"], base / "texts"
            ),
        )
    for module in go["records"]:
        add(
            module["module"],
            module["version"],
            "Go / external cores",
            content_paths(module["texts"], base / "composition/texts"),
        )
    add(
        "kyoresuas/ru-direct",
        "7e14508232595bac5881aa25d31202843a3f6021",
        "Routing data",
        [
            (
                "1126322e2cc8d165adc4c792eeb195717de2bcc7b39be1ce77959d78e87ef685",
                root / "crates/yonik-desktop/assets/ru-direct/LICENSE",
            )
        ],
    )
    if len(entries) > MAX_ENTRIES or sum(map(len, texts.values())) > MAX_TOTAL:
        raise ValueError("Превышен предел notices")
    return entries, texts


def produce(root: Path, output: Path) -> Path:
    entries, texts = collect(root)
    output.mkdir(parents=True, exist_ok=True)
    (output / "index.json").write_text(
        json.dumps(entries, ensure_ascii=False), encoding="utf-8"
    )
    (output / "index.qml").write_text(
        "import QtQml\nQtObject { property var entries: "
        + json.dumps(entries, ensure_ascii=False)
        + " }",
        encoding="utf-8",
    )
    for digest, data in texts.items():
        (output / digest).write_bytes(data)
        (output / (digest + ".qml")).write_text(
            "import QtQml\nQtObject { property string noticeText: "
            + json.dumps(data.decode("utf-8"), ensure_ascii=True)
            + " }",
            encoding="utf-8",
        )
    for name, source in {
        "inventory.json": "packaging/licenses/linux-inventory.json",
        "go-sources.json": "packaging/licenses/composition/go-sources.json",
        "SCOPE.md": "packaging/licenses/composition/P25-SCOPE.md",
        "SOURCE-OBLIGATIONS.md": "packaging/licenses/SOURCE-OBLIGATIONS.md",
        "LICENSE": "LICENSE",
    }.items():
        (output / name).write_bytes(read_bounded(root / source, root))
    # Повторная генерация может оставить старые qrc-файлы в build-каталоге.
    # В пакет включаем только текущий набор, а не содержимое этого каталога.
    (output / "payload.list").write_text(
        "\n".join(
            sorted(
                [
                    "index.json",
                    "inventory.json",
                    "go-sources.json",
                    "SCOPE.md",
                    "SOURCE-OBLIGATIONS.md",
                    "LICENSE",
                    *texts,
                ]
            )
        )
        + "\n",
        encoding="utf-8",
    )
    paths = sorted(
        output / name
        for name in [
            "index.json",
            "index.qml",
            "inventory.json",
            "go-sources.json",
            "SCOPE.md",
            "SOURCE-OBLIGATIONS.md",
            "LICENSE",
            *texts,
            *(digest + ".qml" for digest in texts),
        ]
    )
    qrc = output / "notices.qrc"
    qrc.write_text(
        '<RCC><qresource prefix="/notices">'
        + "".join(
            f'<file alias="{escape(path.name)}">{escape(str(path.absolute()))}</file>'
            for path in paths
        )
        + "</qresource></RCC>",
        encoding="utf-8",
    )
    return qrc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    produce(Path(__file__).resolve().parents[1], args.output)
