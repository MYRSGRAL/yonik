#!/usr/bin/env python3
"""Строгая проверка встроенных пар RU/EN в текущем QML GUI без Qt."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = Path("crates/yonik-desktop/qml/Main.qml")
TOKEN = re.compile(
    r'\s+|//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|[A-Za-z_$][\w$]*|\d+|[^\s]"
)
# Внешние зависимости и воспроизводимые результаты не являются исходниками проекта.
EXCLUDED = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "third_party",
        "target",
        "build",
        "dist",
        "generated",
        "__pycache__",
        ".cache",
    }
)
MAX_ENTRIES = 20_000
MAX_QML_FILES = 512
MAX_SOURCE_BYTES = 2 * 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
PLACEHOLDER = re.compile(r"%L?\d+|%n|\$\{[^{}]+\}|(?<!\{)\{[^{}]*\}(?!\})")


class CatalogError(ValueError):
    """Каталог не соответствует поддерживаемому строгому формату."""


def tokens(source: str) -> list[str]:
    """Убирает комментарии, сохраняя строки как неделимые токены."""
    result: list[str] = []
    for match in TOKEN.finditer(source):
        token = match.group()
        if token.isspace() or token.startswith(("//", "/*")):
            continue
        if token in {'"', "'", "`"} or (
            token == "/" and source[match.start() : match.start() + 2] == "/*"
        ):
            raise CatalogError(
                "Незакрытая строка/комментарий или неподдерживаемый template literal"
            )
        result.append(token)
    return result


def qml_inventory(root: Path) -> list[Path]:
    """Ограниченный стабильный обход исходников без перехода по symlink."""
    if root.is_symlink():
        raise CatalogError("Корень проекта не должен быть symlink")
    paths: list[Path] = []
    visited = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            children = []
            for entry in entries:
                visited += 1
                if visited > MAX_ENTRIES:
                    raise CatalogError(
                        "Превышен лимит inventory; проверка не завершена"
                    )
                if entry.is_symlink() or entry.name in EXCLUDED:
                    continue
                if entry.is_dir(follow_symlinks=False):
                    children.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False) and entry.name.endswith(
                    ".qml"
                ):
                    paths.append(Path(entry.path))
                    if len(paths) > MAX_QML_FILES:
                        raise CatalogError("Превышен лимит QML; проверка не завершена")
            pending.extend(sorted(children, reverse=True))
    return sorted(paths)


def read_source(path: Path) -> str:
    """Читает ограниченный объём; усечение никогда не считается успехом."""
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise CatalogError(f"{path}: превышен лимит размера исходника")
    return data.decode("utf-8")


def literal(token: str) -> str:
    """Декодирует используемый каталогом JSON-совместимый строковый литерал."""
    try:
        value = json.loads(token)
    except (ValueError, TypeError) as error:
        raise CatalogError(f"Ожидался строковый литерал: {token}") from error
    if not isinstance(value, str):
        raise CatalogError(f"Ожидалась строка: {token}")
    return value


def validate_pair(key: str, ru: str, en: str) -> None:
    """Проверяет наличие обоих языков и мультимножество placeholders."""
    if not ru.strip() or not en.strip():
        raise CatalogError(f"{key}: отсутствующий или пустой перевод RU/EN")
    if Counter(PLACEHOLDER.findall(ru)) != Counter(PLACEHOLDER.findall(en)):
        raise CatalogError(f"{key}: несовпадение placeholders RU/EN")


def check_source(source: str, require_catalog: bool = True) -> tuple[int, int]:
    """Разбирает tr-вызовы и карты объявлений; неизвестные формы отклоняет."""
    ts = tokens(source)
    inline = 0
    keys = 0
    maps = 0
    index = 0
    while index < len(ts):
        declaration = ts[index] in {"const", "let", "var"}
        initializer = index + 3
        if declaration and ts[index + 2 : index + 3] == ["="]:
            while ts[initializer : initializer + 1] == ["("]:
                initializer += 1
            if initializer > index + 3 and ts[initializer : initializer + 1] == ["{"]:
                raise CatalogError("Карта в скобках: используйте прямой объект")
        if declaration and ts[index + 2 : index + 4] == ["=", "{"]:
            name = ts[index + 1]
            maps += 1
            index += 4
            seen: set[str] = set()
            while index < len(ts) and ts[index] != "}":
                if ts[index].startswith("'"):
                    raise CatalogError(f"{name}: ключ в неподдерживаемых кавычках")
                key = literal(ts[index]) if ts[index].startswith('"') else ts[index]
                if not IDENTIFIER.fullmatch(key):
                    raise CatalogError(f"{name}: недопустимый ключ {key}")
                if key in seen:
                    raise CatalogError(f"{name}: повторный ключ {key}")
                seen.add(key)
                if ts[index + 1 : index + 3] != [":", "["]:
                    raise CatalogError(f"{name}.{key}: ожидалась пара [RU, EN]")
                if ts[index + 4 : index + 5] != [","] or ts[index + 6 : index + 7] != [
                    "]"
                ]:
                    raise CatalogError(
                        f"{name}.{key}: отсутствует язык или лишний элемент"
                    )
                validate_pair(
                    f"{name}.{key}", literal(ts[index + 3]), literal(ts[index + 5])
                )
                keys += 1
                index += 7
                if ts[index : index + 1] == [","]:
                    index += 1
                elif ts[index : index + 1] != ["}"]:
                    raise CatalogError(f"{name}: ожидалась запятая")
            if not seen:
                raise CatalogError(f"{name}: пустая карта переводов")
            if index >= len(ts):
                raise CatalogError(f"{name}: незакрытая карта")
        elif ts[index : index + 2] == ["tr", "("]:
            end = index + 2
            while end < len(ts) and ts[end] != ")":
                end += 1
            args = ts[index + 2 : end]
            if index > 0 and ts[index - 1] == "function":
                if args != ["ru", ",", "en"]:
                    raise CatalogError("Изменён контракт функции tr")
            elif len(args) == 3 and args[1] == ",":
                validate_pair(f"tr #{inline + 1}", literal(args[0]), literal(args[2]))
                inline += 1
            elif args not in [
                [name, "[", "0", "]", ",", name, "[", "1", "]"]
                for name in ("pair", "reason", "field")
            ]:
                raise CatalogError(f"Неподдерживаемый динамический tr: {args}")
            index = end
        index += 1
    if require_catalog and (not inline or not maps or not keys):
        raise CatalogError("Пустой каталог или изменён механизм переводов")
    return inline, keys


# Только существующие UI-участки P11. Это лексический gate, не JS/QML parser.
SCOPED_UI = (
    ('SettingsRow { objectName: "settingsScheduleButton"', "\n"),
    (
        'SmallLabel { objectName: "routingDiagnosticsScope"',
        '// Конец блока проверки маршрутов.',
    ),
    ("        id: schedulePanel", "        id: appearancePanel"),
)
SCOPED_ROUTING_ELEMENTS = frozenset(
    {
        "routingDiagnosticsScope",
        "routingDiagnosticsIncomplete",
        "routingExplainTarget",
        "routingExplainButton",
        "routingExplanation",
    }
)
# Технические objectName, enum/command IDs, разделители и цвет. Пользовательские
# предложения вне tr запрещены на обоих языках, включая только латинские строки.
SCOPED_TECHNICAL = frozenset(
    {
        "settingsScheduleButton",
        "↻",
        "schedule",
        "routingDiagnosticsScope",
        "routingDiagnosticsIncomplete",
        "#",
        " ← ",
        "shadowed",
        "routingExplainTarget",
        "routingExplainButton",
        "routing_explain",
        "routingExplanation",
        "",
        "fixture",
        " · ",
        "application_witness_missing",
        "dns_witness_missing",
        "dns_missing",
        "evaluation_rejected",
        "xray",
        "startupTab",
        "updatesTab",
        "subscriptionInterval",
        "set_subscription_schedule",
        "subscriptionBackground",
        "autostartIntoTray",
        "startupAutoconnect",
        "confirmStartupTarget",
        "durability_unknown",
        "error",
        "startup_xdg",
        "blocked",
        "durable",
        "—",
        "preferences_write",
        "#e6bc83",
    }
)


def check_scoped_ui(source: str) -> int:
    """Проверяет все литералы в трёх ограниченных contiguous участках Main."""
    count = 0
    for start, end in SCOPED_UI:
        if source.count(start) != 1:
            raise CatalogError(f"P11: граница отсутствует или неоднозначна: {start}")
        if end != "\n" and source.count(end) != 1:
            raise CatalogError(f"P11: конечная граница неоднозначна: {end}")
        offset = source.index(start)
        stop = source.find(end, offset + len(start))
        if stop < 0:
            raise CatalogError(f"P11: конечная граница отсутствует: {end}")
        ts = tokens(source[offset:stop])
        if "routingDiagnosticsScope" in start:
            # Граница должна следовать за целыми sibling-элементами, а не
            # обрезать обязательный элемент после его objectName.
            depth = 0
            for token in ts:
                if token == "{":
                    depth += 1
                elif token == "}":
                    depth -= 1
                    if depth < 0:
                        raise CatalogError("P11: граница пересекает QML-элемент")
            if depth:
                raise CatalogError("P11: граница обрезает QML-элемент")
            names = [
                literal(ts[i + 2])
                for i in range(len(ts) - 2)
                if ts[i : i + 2] == ["objectName", ":"]
                and ts[i + 2].startswith(('"', "'"))
            ]
            if any(names.count(name) != 1 for name in SCOPED_ROUTING_ELEMENTS):
                raise CatalogError("P11: обязательные элементы Routing вышли из scope")
        index = 0
        while index < len(ts):
            if ts[index : index + 2] == ["tr", "("]:
                if ts[index + 3 : index + 4] != [","] or ts[index + 5 : index + 6] != [
                    ")"
                ]:
                    raise CatalogError("P11: разрешены только literal tr-пары")
                validate_pair("P11", literal(ts[index + 2]), literal(ts[index + 4]))
                count += 1
                index += 6
                continue
            if ts[index].startswith(('"', "'")):
                value = literal(ts[index])
                if value not in SCOPED_TECHNICAL:
                    raise CatalogError(f"P11: UI-литерал вне tr: {value}")
            index += 1
    return count


def check_cpp_source(source: str) -> int:
    """Проверяет существующие QStringLiteral-пары tray, не пользовательские имена."""
    pattern = re.compile(
        r'english\s*\?\s*QStringLiteral\(("(?:\\.|[^"\\])*")\)\s*:\s*QStringLiteral\(("(?:\\.|[^"\\])*")\)'
    )
    matches = list(pattern.finditer(source))
    if not matches or len(matches) != len(re.findall(r"\benglish\s*\?", source)):
        raise CatalogError("Неизвестная форма RU/EN tray")
    for index, match in enumerate(matches):
        validate_pair(f"tray #{index}", literal(match[2]), literal(match[1]))
    return len(matches)


def main() -> int:
    """Возвращает ненулевой код при любой ошибке чтения или проверки."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        paths = qml_inventory(args.root)
        if args.root / CATALOG not in paths:
            raise CatalogError("Основной каталог отсутствует в inventory")
        check_scoped_ui(read_source(args.root / CATALOG))
        inline = keys = 0
        for path in paths:
            try:
                pairs, entries = check_source(
                    read_source(path), path == args.root / CATALOG
                )
            except CatalogError as error:
                raise CatalogError(f"{path.relative_to(args.root)}: {error}") from error
            inline += pairs
            keys += entries
        check_cpp_source(
            read_source(args.root / "crates/yonik-desktop/src/application.cpp")
        )
    except (OSError, ValueError, IndexError) as error:
        parser.exit(1, f"Ошибка переводов: {error}\n")
    print(
        f"RU/EN: проверено {inline} inline-пар и {keys} ключей карт; QML: {len(paths)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
