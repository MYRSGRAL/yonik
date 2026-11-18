"""Мутации доверенного набора notices."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import compile_notices as notices


class NoticesTests(unittest.TestCase):
    def test_real_inventory(self) -> None:
        entries, texts = notices.collect(Path(__file__).parents[2])
        self.assertEqual(len(entries), 225 + 173 + 1)
        ru_direct = next(
            entry for entry in entries if entry["name"] == "kyoresuas/ru-direct"
        )
        license_file = (
            Path(__file__).parents[2] / "crates/yonik-desktop/assets/ru-direct/LICENSE"
        )
        self.assertEqual(
            [texts[digest] for digest in ru_direct["hashes"]],
            [license_file.read_bytes()],
        )
        self.assertTrue(texts)

    def test_mutations(self) -> None:
        root = Path(__file__).parents[2]
        original = notices.read_bounded
        for mutation in (b"", b"wrong", b"x" * (4 * 1024 * 1024 + 1)):
            with self.subTest(size=len(mutation)):

                def read(path: Path, allowed: Path) -> bytes:
                    if path.parent.name == "texts":
                        return mutation
                    return original(path, allowed)

                with patch.object(notices, "read_bounded", read):
                    with self.assertRaises(ValueError):
                        notices.collect(root)

    def test_safe_reader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "text").symlink_to("/etc/passwd")
            with (root / "oversize").open("wb") as stream:
                stream.truncate(4 * 1024 * 1024 + 1)
            for name in ("text", "missing", "../outside", "oversize"):
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    notices.read_bounded(root / name, root)

    def test_resource_bytes(self) -> None:
        root = Path(__file__).parents[2]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            notices.produce(root, output)
            entries = json.loads((output / "index.json").read_text())
            for entry in entries:
                for digest in entry["hashes"]:
                    self.assertEqual(
                        notices.hashlib.sha256(
                            (output / digest).read_bytes()
                        ).hexdigest(),
                        digest,
                    )

    def test_reused_output_packages_only_current_notices(self) -> None:
        root = Path(__file__).parents[2]
        entries, texts = notices.collect(root)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "notices"
            notices.produce(root, output)
            current = entries[:1]
            keep = {digest for entry in current for digest in entry["hashes"]}
            removed = set(texts) - keep
            self.assertTrue(removed)
            with patch.object(
                notices,
                "collect",
                return_value=(current, {key: texts[key] for key in keep}),
            ):
                notices.produce(root, output)
            # Исполняем настоящий package(), заменяя только внешние инструменты.
            source = output.parent / "src"
            source.mkdir()
            (source / "yonik-notices").symlink_to(output, target_is_directory=True)
            recipe = root / "packaging/arch/PKGBUILD"
            revision = "6cf65a4cf9760a7df68b8eee10f012770b38604d"
            (source / ("yonik-" + revision)).symlink_to(root, target_is_directory=True)
            package = output.parent / "pkg"
            (package / "usr/share/applications").mkdir(parents=True)
            result = subprocess.run(
                [
                    "bash",
                    "-eu",
                    "-c",
                    """
source "$1"
srcdir="$2"; pkgdir="$3"; CARGO_TARGET_DIR="$2/target"
python3() { :; }
install() { if [[ "$1" == -m644 ]]; then printf '%s\\n' "${2##*/}"; fi; }
package
""",
                    "fixture",
                    str(recipe),
                    str(source),
                    str(package),
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            self.assertFalse(removed & set(result.stdout.splitlines()))
            names = (output / "payload.list").read_text().splitlines()
            self.assertTrue(keep <= set(names))
            self.assertFalse(removed & set(names))
            self.assertTrue(all((output / name).is_file() for name in names))
            self.assertEqual(len(names), len(set(names)))
            self.assertFalse(any(name.endswith((".qml", ".qrc")) for name in names))
