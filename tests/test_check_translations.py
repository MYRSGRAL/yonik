"""Проверка реального каталога и повреждений обоих способов перевода."""

import contextlib
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_translations", ROOT / "tools/check_translations.py"
)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
SOURCE = 'const messages = {ready: ["Готово", "Ready"]}; tr("Привет", "Hello")'


class TranslationTests(unittest.TestCase):
    def test_current_catalog(self) -> None:
        inline, keys = checker.check_source((ROOT / checker.CATALOG).read_text())
        self.assertGreater(inline, 0)
        self.assertGreater(keys, 0)

    def test_p11_scoped_inventory(self) -> None:
        source = (ROOT / checker.CATALOG).read_text()
        self.assertGreater(checker.check_scoped_ui(source), 15)
        for old, new in [
            (
                'window.tr("Обновления подписок", "Subscription updates")',
                '"Обновления подписок"',
            ),
            (
                'window.tr("Проверить правило", "Explain saved draft")',
                '"Explain saved draft"',
            ),
            ("id: schedulePanel", "id: renamedPanel"),
            (
                'text: "#" + modelData.rule_id',
                'text: "Новая строка" + modelData.rule_id',
            ),
        ]:
            with self.subTest(new=new):
                self.assertIn(old, source)
                with self.assertRaises(checker.CatalogError):
                    checker.check_scoped_ui(source.replace(old, new))
        # Вне оговорённых границ этот gate не претендует на покрытие.
        checker.check_scoped_ui(source + '\nLabel { text: "Вне scope" }')

    def test_p11_nested_layout_cannot_hide_untranslated_explanation(self) -> None:
        source = (ROOT / checker.CATALOG).read_text()
        header = re.search(
            r'(?m)^( *)PlainLabel \{\n +objectName: "routingExplanation"', source
        )
        pair = 'window.tr("причина недоступна", "reason unavailable")'
        self.assertIsNotNone(header)
        assert header is not None
        self.assertIn(pair, source)
        changed = (
            source[: header.start()]
            + f"{header[1]}RowLayout {{}}\n"
            + source[header.start() :]
        )
        changed = changed.replace(pair, '"Причина только по-русски"')
        with self.assertRaises(checker.CatalogError):
            checker.check_scoped_ui(changed)
        with (
            patch.object(sys, "argv", ["check_translations", "--root", str(ROOT)]),
            patch.object(
                checker, "qml_inventory", return_value=[ROOT / checker.CATALOG]
            ),
            patch.object(checker, "read_source", return_value=changed),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            checker.main()
        self.assertEqual(error.exception.code, 1)

    def test_p11_boundary_cannot_cut_required_element(self) -> None:
        source = (ROOT / checker.CATALOG).read_text()
        boundary = checker.SCOPED_UI[1][1]
        self.assertEqual(source.count(boundary), 1)
        changed = source.replace(boundary, "                RowLayout {")
        name = 'objectName: "routingExplanation"'
        changed = changed.replace(name, name + "\n" + boundary + " }", 1)
        changed = changed.replace(
            'window.tr("причина недоступна", "reason unavailable")',
            '"Причина только по-русски"',
        )
        with self.assertRaises(checker.CatalogError):
            checker.check_scoped_ui(changed)

    def test_p11_required_explanation_cannot_disappear_from_scope(self) -> None:
        source = (ROOT / checker.CATALOG).read_text()
        changed = source.replace('objectName: "routingExplanation"', 'objectName: ""')
        with self.assertRaises(checker.CatalogError):
            checker.check_scoped_ui(changed)

    def test_tray_pairs(self) -> None:
        source = (ROOT / "crates/yonik-desktop/src/application.cpp").read_text()
        self.assertEqual(checker.check_cpp_source(source), 9)
        with self.assertRaises(checker.CatalogError):
            checker.check_cpp_source(
                source.replace('QStringLiteral("Connect")', 'QStringLiteral("")')
            )

    def test_owned_component(self) -> None:
        path = ROOT / checker.CATALOG.parent / "DiagnosticsExport.qml"
        source = path.read_text()
        self.assertEqual(checker.check_source(source, False), (4, 0))
        with self.assertRaises(checker.CatalogError):
            checker.check_source(source.replace('"Copied"', '""'), False)

    def test_corruptions(self) -> None:
        for old, new in [
            ('"Готово", "Ready"', '"Готово"'),
            ('"Готово", "Ready"', '"Готово", ""'),
            ('"Привет", "Hello"', '"Привет", " "'),
            ('"Привет", "Hello"', '"Привет %1", "Hello %2"'),
            ('"Готово", "Ready"', '"Готово {name}", "Ready"'),
            ('"Готово", "Ready"', '"Готово", "Ready", "Extra"'),
            ("ready:", 'ready: ["Да", "Yes"], ready:'),
            ('tr("Привет", "Hello")', "tr(value, other)"),
        ]:
            with self.subTest(new=new), self.assertRaises(checker.CatalogError):
                checker.check_source(SOURCE.replace(old, new))

    def test_escaped_and_comments(self) -> None:
        checker.check_source(SOURCE + '\n// tr("bad", "")\n/* const x = { */')

    def test_placeholder_multiplicity(self) -> None:
        with self.assertRaises(checker.CatalogError):
            checker.validate_pair("key", "%1 %1", "%1")

    def test_empty_catalog(self) -> None:
        with self.assertRaises(checker.CatalogError):
            checker.check_source("")

    def test_other_declarations_are_checked(self) -> None:
        for declaration in ("let", "var"):
            with self.subTest(declaration=declaration):
                source = SOURCE.replace("const", declaration)
                self.assertEqual(checker.check_source(source), (1, 1))
                with self.assertRaises(checker.CatalogError):
                    checker.check_source(SOURCE + source.replace('"Готово"', '""'))

    def test_wrapped_maps_are_rejected(self) -> None:
        for opening, closing in (("(", ")"), ("((", "))")):
            with self.subTest(opening=opening), self.assertRaises(checker.CatalogError):
                checker.check_source(
                    SOURCE + f'const wrapped = {opening}{{ready: ["Да"]}}{closing};'
                )

    def test_single_quoted_keys_are_rejected(self) -> None:
        with self.assertRaises(checker.CatalogError):
            checker.check_source(
                SOURCE + 'const m = {ready: ["Да", "Yes"], \'ready\': ["Нет", "No"]};'
            )


class InventoryTests(unittest.TestCase):
    def test_all_project_qml(self) -> None:
        paths = checker.qml_inventory(ROOT)
        self.assertIn(ROOT / checker.CATALOG.parent / "LogsView.qml", paths)
        self.assertIn(ROOT / checker.CATALOG.parent / "DiagnosticsExport.qml", paths)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                checker.check_source(
                    checker.read_source(path), path == ROOT / checker.CATALOG
                )

    def test_component_mutations_cli(self) -> None:
        """Main неизменён: дефект только в отдельном/будущем компоненте."""
        with tempfile.TemporaryDirectory(prefix="yonik-translations-") as directory:
            root = Path(directory)
            main = root / checker.CATALOG
            main.parent.mkdir(parents=True)
            main_source = (ROOT / checker.CATALOG).read_text()
            main.write_text(main_source, encoding="utf-8")
            cpp = root / "crates/yonik-desktop/src/application.cpp"
            cpp.parent.mkdir()
            cpp.write_text(
                'english ? QStringLiteral("Ready") : QStringLiteral("Готово")',
                encoding="utf-8",
            )
            for name in (
                "LogsView.qml",
                "DiagnosticsExport.qml",
                "future/deep/Card.qml",
            ):
                component = main.parent / name
                component.parent.mkdir(parents=True, exist_ok=True)
                for content in (
                    'tr("Да", "")',
                    'const m = {ok: ["Да", "Yes"], ok: ["Нет", "No"]}',
                    'const m = {42: ["Да", "Yes"]}',
                    'const m = {"bad-key": ["Да", "Yes"]}',
                    'tr(select(value), "Yes")',
                ):
                    component.write_text(content, encoding="utf-8")
                    with self.subTest(name=name, content=content):
                        with patch.object(
                            sys, "argv", ["checker", "--root", str(root)]
                        ):
                            with contextlib.redirect_stderr(io.StringIO()):
                                with self.assertRaises(SystemExit) as raised:
                                    checker.main()
                        self.assertEqual(raised.exception.code, 1)
                        self.assertEqual(main.read_text(encoding="utf-8"), main_source)
                component.write_text('tr("Да", "Yes")', encoding="utf-8")
            with patch.object(sys, "argv", ["checker", "--root", str(root)]):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(checker.main(), 0)

    def test_inventory_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yonik-inventory-") as directory:
            root = Path(directory)
            component = root / "nested" / "Card.qml"
            component.parent.mkdir()
            component.write_text("", encoding="utf-8")
            for name in checker.EXCLUDED:
                excluded = root / name
                excluded.mkdir()
                (excluded / "Ignored.qml").write_text("", encoding="utf-8")
            (root / "linked").symlink_to(component.parent, target_is_directory=True)
            (root / "Link.qml").symlink_to(component)
            self.assertEqual(checker.qml_inventory(root), [component])
            with patch.object(checker, "MAX_ENTRIES", 1):
                with self.assertRaises(checker.CatalogError):
                    checker.qml_inventory(root)
            with patch.object(checker, "MAX_QML_FILES", 0):
                with self.assertRaises(checker.CatalogError):
                    checker.qml_inventory(root)
            with patch.object(checker, "MAX_SOURCE_BYTES", 1):
                component.write_text("abc", encoding="utf-8")
                with self.assertRaises(checker.CatalogError):
                    checker.read_source(component)

    def test_lexical_controls(self) -> None:
        source = r"""function tr(ru, en) { return english ? en : ru }
        // tr("Нет", "")
        /* const bad = {42: ["Нет"]}; */
        const label = "tr(ignored, ignored)";
        text: wrap(flag ? root.tr("Скажи \"да\"", "Say \"yes\"") : tr("Нет", "No"))
        """
        self.assertEqual(checker.check_source(source, False), (2, 0))
        for unsupported in (
            'tr(f(a, b), "Yes")',
            'tr("Да", getText())',
            "`dynamic ${value}`",
            "/* unfinished",
            '"unfinished',
        ):
            with (
                self.subTest(source=unsupported),
                self.assertRaises(checker.CatalogError),
            ):
                checker.check_source(unsupported, False)


if __name__ == "__main__":
    unittest.main()
