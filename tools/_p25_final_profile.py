"""Фиксированный opt-in профиль build-time CXX metadata; без shell/discovery."""

from __future__ import annotations

import fcntl
import gzip
import hashlib
import io
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import zlib
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Callable, Iterator

from _p25_capture_producer import _directory, _write
from p25_capture_build_closure import (
    MAX_FILE,
    MAX_FILES,
    MAX_METADATA,
    Reader,
    object_fields,
    parse,
    relative,
    require,
)

PROFILE = {
    "id": "p25-final-cxx-v1",
    "compiler": "/usr/bin/g++",
    "qt_query": ["/usr/lib/qt6/bin/qtpaths", "--qt-version"],
    "sdk_root": "/usr",
    "registry_source_root": "/home/myrs/.cargo/registry/src",
    "registry_unpacked_byte_cap": 64 * 1024 * 1024,
    "dependency_flags": ["-MD", "-MF"],
    "internal_observed_schema": 2,
    "probe_source_cap": 4096,
    "alias_count_cap": 128,
    "alias_chain_cap": 4,
    "deadline_seconds": 300,
    "stream_cap": MAX_METADATA,
    "observed_metadata_cap": 8 * MAX_METADATA,
    "dependency_row_cap": 10000,
}
Runner = Callable[[int, list[str], Path, dict[str, str]], tuple[int, bytes, bytes]]


def dependencies(raw: bytes) -> list[str]:
    """Одна Make rule: escapes, continuation и $$; никогда Make execution."""
    require(len(raw) <= MAX_METADATA, "Depfile превышает cap")
    text = raw.decode("utf-8", errors="strict")
    words: list[str] = []
    token = ""
    colon = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 1
            require(i < len(text), "Оборванный Make escape")
            if text[i] == "\n":
                if token:
                    words.append(token)
                    token = ""
            else:
                require(text[i] in " \\#:$\t", "Неизвестный Make escape")
                token += text[i]
        elif char == "$":
            require(text[i : i + 2] == "$$", "Make expansion запрещён")
            token += "$"
            i += 1
        elif char == ":":
            require(not colon and bool(token or words), "Несколько/пустой Make rule")
            colon = True
            words = []
            token = ""
        elif char in " \t\r\n":
            if token:
                words.append(token)
                token = ""
            if char == "\n":
                require(not text[i:].strip(), "Несколько Make rules")
        else:
            require(ord(char) >= 32 and char != "#", "Неэкранированный Make token")
            token += char
        require(len(words) <= MAX_FILES, "Слишком много dependencies")
        i += 1
    if token:
        words.append(token)
    require(colon and bool(words) and len(words) <= MAX_FILES, "Пустой depfile")
    return list(dict.fromkeys(words))


def compile_arguments(argv: list[str], depfile: Path) -> list[str]:
    require(0 < len(argv) <= MAX_FILES, "Неверный CXX argv count")
    require(
        all(
            isinstance(arg, str)
            and 0 < len(arg) <= 4096
            and "\x00" not in arg
            and not arg.startswith("@")
            for arg in argv
        ),
        "Response/неверный argv",
    )
    require(sum(map(len, argv)) <= MAX_METADATA, "CXX argv cap")
    require(
        not any(
            arg.startswith(("-MD", "-MMD", "-MF", "-MT", "-MQ", "-MP"))
            or arg in ("-M", "-MM")
            or arg.startswith("-Wp,-M")
            for arg in argv
        ),
        "Конфликт dependency flags",
    )
    return [*argv, "-MD", "-MF", str(depfile)] if "-c" in argv else list(argv)


PROBE_CAP = 4096
FLAG_BODY = b"int main(void) { return 0; }"
FAMILY_HASH = "97ca4b021495611e828becea6187add37414186a16dfedd26c2947cbce6e8b2f"
FLAG_PREFIX = [
    "-O0",
    "-ffunction-sections",
    "-fdata-sections",
    "-fPIC",
    "-m64",
    "-march=x86-64",
    "-Wall",
    "-Wextra",
]
FLAG_OPTIONS = {"/Zc:__cplusplus", "/permissive-", "/bigobj", "-Wa,-mbig-obj"}


def probe_shape(argv: list[str], build: Path) -> tuple[str, str | None]:
    """Закрытый cc-1.11.1 contract, до запуска compiler."""
    if argv == ["-?"]:
        return "family-query", None
    if len(argv) == 2 and argv[0] == "-E":
        path = Path(argv[1])
        if path.is_relative_to(build) and re.fullmatch(
            r"release/build/(?:link-cplusplus|cxx|cxx-qt|cxx-qt-lib|yonik-desktop)-[0-9a-f]{16}/out/[0-9]{1,20}detect_compiler_family\.c",
            path.relative_to(build).as_posix(),
        ):
            return "family-preprocess", str(path)
    if (
        len(argv) == 13
        and argv[:8] == FLAG_PREFIX
        and argv[8] in FLAG_OPTIONS
        and argv[9] == "-o"
        and argv[11] == "-c"
    ):
        path = Path(argv[12])
        if (
            path.is_relative_to(build)
            and re.fullmatch(
                r"release/build/(?:cxx-qt|cxx-qt-lib|yonik-desktop)-[0-9a-f]{16}/out/flag_check\.cpp",
                path.relative_to(build).as_posix(),
            )
            and argv[10] == str(path.with_suffix(""))
        ):
            return "flag-support", str(path)
    return "compile" if "-c" in argv else "other", None


def validate_purpose(row: dict, build: Path) -> bool:
    """Pure проверка declared proof; JSON не даёт файловой authority."""
    require(
        type(row["schema"]) is int and row["schema"] in (1, 2), "Unknown CXX schema"
    )
    require(type(row["exit"]) is int, "Invalid CXX exit")
    if row["schema"] == 1:
        require(
            "purpose" not in row and "probe" not in row and row["exit"] == 0,
            "Legacy unsuccessful/proof",
        )
        return False
    require(isinstance(row["original_argv"], list), "CXX argv type")
    compile_arguments(row["original_argv"], build / "unused.d")
    purpose, source = probe_shape(row["original_argv"], build)
    require(row["purpose"] == purpose, "Purpose binding mismatch")
    proof = row["probe"]
    if source is None:
        require(proof is None, "Unexpected probe source")
    else:
        object_fields(
            proof, {"source", "bytes_hex", "sha256"}, {"source", "bytes_hex", "sha256"}
        )
        require(
            proof["source"] == source
            and isinstance(proof["bytes_hex"], str)
            and len(proof["bytes_hex"]) <= 2 * PROBE_CAP,
            "Probe source/cap",
        )
        raw = bytes.fromhex(proof["bytes_hex"])
        digest = hashlib.sha256(raw).hexdigest()
        require(
            digest == proof["sha256"]
            and (
                raw == FLAG_BODY if purpose == "flag-support" else digest == FAMILY_HASH
            ),
            "Probe source body/hash",
        )
    probe = purpose in {"family-query", "family-preprocess", "flag-support"}
    require(
        row["exit"]
        in (
            {1}
            if purpose == "family-query"
            else {0, 1}
            if purpose == "flag-support"
            else {0}
        ),
        "Unsuccessful CXX purpose",
    )
    if probe:
        require(
            row["argv"] == [PROFILE["compiler"], *row["original_argv"]],
            "Probe argv binding",
        )
        require(
            row["unit"] is None
            and row["depfile"] is None
            and "normalized_depfile" not in row
            and "raw_depfile_sha256" not in row,
            "Probe claims compiled unit",
        )
    elif purpose == "compile":
        require(
            isinstance(row["depfile"], str)
            and re.fullmatch(r"p25capture/[0-9]+\.d", row["depfile"]),
            "Compile depfile binding",
        )
        units = [
            arg
            for arg in row["original_argv"]
            if arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++"))
        ]
        require(
            len(units) == 1 and row["unit"] == str(Path(row["cwd"]) / units[0]),
            "Compile unit binding",
        )
        require(
            row["argv"]
            == [
                PROFILE["compiler"],
                *compile_arguments(row["original_argv"], build / row["depfile"]),
            ],
            "Compile argv binding",
        )
    else:
        require(
            row["unit"] is None and row["depfile"] is None and proof is None,
            "Other claims unit",
        )
    return probe


ALIAS_CAP = 128
ALIAS_LINK_CAP = 4


def forest(path: Path, build: Path, header: bool = True) -> bool:
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(build):
        return False
    local = path.relative_to(build).as_posix()
    return bool(
        re.fullmatch(
            r"release/build/(?:cxx-qt|cxx-qt-lib|yonik-desktop)-[0-9a-f]{16}/out/cxxqtbuild/include/(?:cxx-qt|cxx-qt-lib)(?:/[A-Za-z0-9_.-]+)*",
            local,
        )
    ) and (not header or path.suffix in {".h", ".hpp", ".hxx"})


def alias_target(path: Path, build: Path, stack: ExitStack) -> tuple[Path, list[dict]]:
    """Только generated include forest; NOFOLLOW traversal и bounded links."""
    require(forest(path, build), "Unknown alias forest/header")
    current = path
    links = []
    stamps = []
    seen = set()
    while True:
        require(current not in seen, "Alias cycle")
        seen.add(current)
        directory = _directory(build)
        prefix = build
        changed = False
        try:
            parts = current.relative_to(build).parts
            for index, part in enumerate(parts):
                info = os.stat(part, dir_fd=directory, follow_symlinks=False)
                prefix /= part
                identity = (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
                stamps.append((prefix, identity))
                if stat.S_ISLNK(info.st_mode):
                    require(len(links) < ALIAS_LINK_CAP, "Alias chain cap")
                    target = os.readlink(part, dir_fd=directory)
                    candidate = (
                        Path(target)
                        if Path(target).is_absolute()
                        else prefix.parent / target
                    )
                    require(
                        forest(prefix, build, False)
                        and forest(candidate, build, False),
                        "Alias target escape/forest",
                    )
                    links.append({"path": str(prefix), "target": target})
                    current = candidate.joinpath(*parts[index + 1 :])
                    require(forest(current, build), "Alias canonical header")
                    changed = True
                    break
                if index < len(parts) - 1:
                    nested = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    os.close(directory)
                    directory = nested
                else:
                    require(stat.S_ISREG(info.st_mode), "Alias target not regular")
        finally:
            os.close(directory)
        if not changed:
            break

    def verify() -> None:
        for path, expected in stamps:
            parent = _directory(path.parent)
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                actual = (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )
                require(actual == expected, "Alias input changed")
            finally:
                os.close(parent)

    # Проверяем каждый путь от root: pathname ancestors также остаются bound.
    stack.callback(verify)
    return current, links


def validate_aliases(aliases: dict, build: Path) -> dict[str, str]:
    require(
        isinstance(aliases, dict) and len(aliases) <= ALIAS_CAP, "Alias map cap/type"
    )
    mapping = {}
    for origin, value in aliases.items():
        require(
            isinstance(origin, str) and forest(Path(origin), build),
            "Alias origin forest",
        )
        object_fields(
            value, {"canonical", "links", "sha256"}, {"canonical", "links", "sha256"}
        )
        require(
            isinstance(value["canonical"], str)
            and forest(Path(value["canonical"]), build),
            "Alias canonical forest",
        )
        links = value["links"]
        require(
            isinstance(links, list) and 0 < len(links) <= ALIAS_LINK_CAP,
            "Alias links cap",
        )
        current = Path(origin)
        visited = {current}
        for link in links:
            object_fields(link, {"path", "target"}, {"path", "target"})
            require(
                isinstance(link["path"], str) and isinstance(link["target"], str),
                "Alias link type",
            )
            path, target = Path(link["path"]), Path(link["target"])
            require(
                forest(path, build, False) and current.is_relative_to(path),
                "Alias link binding",
            )
            target = target if target.is_absolute() else path.parent / target
            require(forest(target, build, False), "Alias target forest")
            current = target / current.relative_to(path)
            require(current not in visited, "Alias cycle")
            visited.add(current)
        require(
            str(current) == value["canonical"]
            and isinstance(value["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None,
            "Alias canonical/hash binding",
        )
        mapping[origin] = str(current)
    return mapping


def validate_observed_extensions(observed: dict, files: list[dict]) -> dict[str, str]:
    require(
        type(observed["schema"]) is int and observed["schema"] in (1, 2),
        "Unknown observed schema",
    )
    require(
        ("aliases" in observed) == (observed["schema"] == 2),
        "Observed alias schema binding",
    )
    build = Path(observed["config"]["build"])
    aliases = validate_aliases(observed.get("aliases", {}), build)
    whitelist = {(row["root"], row["path"]): row for row in files}
    for origin, canonical in aliases.items():
        row = whitelist.get(("build", Path(canonical).relative_to(build).as_posix()))
        require(
            row is not None
            and row["kind"] == "generated"
            and row["sha256"] == observed["aliases"][origin]["sha256"],
            "Alias outside retained whitelist",
        )
    return aliases


@contextmanager
def trusted_tool(alias: str) -> Iterator[tuple[int, dict]]:
    require(alias in (PROFILE["compiler"], PROFILE["qt_query"][0]), "Не fixed tool")
    path = Path(alias).resolve(strict=True)
    require(path.is_relative_to(Path(PROFILE["sdk_root"])), "Tool вне trusted SDK root")
    parent = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE,
            "Неверный compiler/query file",
        )
        digest = hashlib.sha256()
        count = 0
        while chunk := os.read(fd, 65536):
            count += len(chunk)
            require(count <= MAX_FILE, "Tool bytes cap")
            digest.update(chunk)
        after = os.fstat(fd)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and count == before.st_size,
            "Tool изменился",
        )
        checksum = digest.hexdigest()
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd, {"path": str(path), "sha256": checksum}
    finally:
        os.close(fd)


def execute(
    fd: int, argv: list[str], cwd: Path, env: dict[str, str]
) -> tuple[int, bytes, bytes]:
    """Pipe drain с deadline/caps; всегда завершает собственную process group."""
    outputs = [bytearray(), bytearray()]
    with subprocess.Popen(
        argv,
        executable=f"/proc/self/fd/{fd}",
        pass_fds=(fd,),
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            deadline = time.monotonic() + PROFILE["deadline_seconds"]
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    require(stream is not None, "Нет compiler pipe")
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    require(time.monotonic() < deadline, "Compiler/query deadline")
                    for key, _ in selector.select(
                        min(0.1, max(0, deadline - time.monotonic()))
                    ):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output = outputs[key.data]
                        require(
                            len(output) + len(chunk) <= PROFILE["stream_cap"],
                            "Compiler/query log cap",
                        )
                        output.extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, bytes(outputs[0]), bytes(outputs[1])
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _reserve(build: Path) -> int:
    directory = _directory(build / "p25capture")
    try:
        fd = os.open(
            "count",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
            and info.st_size <= 16,
            "Неверный counter",
        )
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "Counter lock deadline")
                time.sleep(0.01)
        raw = os.read(fd, 16)
        count = int(raw or b"0")
        require(0 <= count < MAX_FILES, "Invocation cap")
        os.pwrite(fd, str(count + 1).encode(), 0)
        os.fsync(fd)
        return count
    finally:
        os.close(fd)


def _identity(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode), "Registry symlink")
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _pax_fields(payload: bytes) -> None:
    """Ограничиваем metadata до того, как tarfile начнёт её интерпретацию."""
    position = 0
    fields = 0
    while position < len(payload):
        space = payload.find(b" ", position, position + 21)
        require(space > position, "TAR PAX length")
        digits = payload[position:space]
        require(digits.isdigit(), "TAR PAX length")
        end = position + int(digits)
        require(space + 1 < end <= len(payload), "TAR PAX bounds")
        record = payload[space + 1 : end]
        require(record.endswith(b"\n") and b"=" in record, "TAR PAX record")
        key = record[:-1].split(b"=", 1)[0]
        require(bool(key) and not key.startswith(b"GNU.sparse"), "TAR sparse PAX")
        # Все допустимые файлы меньше предела обычного size header. Override
        # изменил бы смещения tarfile относительно предварительного прохода.
        require(key != b"size", "TAR PAX size override")
        fields += 1
        require(fields <= MAX_FILES, "TAR PAX field cap")
        position = end


@contextmanager
def _registry_tar(
    archive: bytes, *, gzip_encoded: bool = True
) -> Iterator[tarfile.TarFile]:
    """Bounded decoded stream, physical headers и строгий конец TAR; без extract."""
    cap = (
        min(MAX_FILE, PROFILE["registry_unpacked_byte_cap"])
        if gzip_encoded
        else MAX_FILE
    )
    require(len(archive) <= cap, "TAR compressed byte cap")
    try:
        with tempfile.TemporaryFile() as expanded, ExitStack() as stack:
            source = io.BytesIO(archive)
            decoded = (
                stack.enter_context(gzip.GzipFile(fileobj=source))
                if gzip_encoded
                else source
            )
            size = 0
            while chunk := decoded.read(min(65536, cap - size + 1)):
                size += len(chunk)
                require(size <= cap, "TAR decoded byte cap")
                expanded.write(chunk)
            require(size >= 1024 and size % 512 == 0, "TAR block bounds")
            expanded.seek(0)
            headers = 0
            metadata_chain = 0
            while True:
                header = expanded.read(512)
                require(len(header) == 512, "TAR missing end marker")
                if header == bytes(512):
                    require(expanded.read(512) == bytes(512), "TAR end marker")
                    while tail := expanded.read(65536):
                        require(not any(tail), "TAR trailing data")
                    break
                headers += 1
                require(headers <= MAX_FILES * 4, "TAR physical header cap")
                member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
                require(member.type != tarfile.GNUTYPE_SPARSE, "TAR sparse header")
                metadata = member.type in (b"x", b"g", b"X", b"L", b"K")
                require(
                    member.isreg() or metadata or member.size == 0,
                    "TAR nonregular payload",
                )
                padded = (member.size + 511) // 512 * 512
                require(
                    member.size >= 0 and expanded.tell() + padded <= size,
                    "TAR physical member bounds",
                )
                if metadata:
                    metadata_chain += 1
                    require(metadata_chain <= 8, "TAR metadata chain cap")
                    require(member.size <= MAX_METADATA, "TAR metadata cap")
                    payload = expanded.read(member.size)
                    if member.type in (b"x", b"g", b"X"):
                        _pax_fields(payload)
                    expanded.seek(padded - member.size, os.SEEK_CUR)
                else:
                    metadata_chain = 0
                    expanded.seek(padded, os.SEEK_CUR)
            expanded.seek(0)
            with tarfile.open(fileobj=expanded, mode="r:") as tar:
                yield tar
    except (tarfile.TarError, EOFError, zlib.error) as error:
        raise ValueError("Некорректный TAR stream") from error


@contextmanager
def registry_package(source: Path, package: Path) -> Iterator[set[str]]:
    """Один выбранный Cargo package: lock → archive → extracted bytes, без discovery."""
    base = Path(PROFILE["registry_source_root"])
    require(
        package.is_absolute()
        and ".." not in package.parts
        and package.parent == base / "index.crates.io-1949cf8c6b5b557f",
        "Registry cwd не exact canonical package",
    )
    with ExitStack() as stack:
        reader = Reader(
            {"source": source, "build": base, "sdk": base.parent / "cache"}, stack
        )
        identities: dict[Path, tuple[int, ...]] = {}

        def remember(path: Path) -> None:
            identities.setdefault(path, _identity(path))

        def read(root: str, local: str, limit: int) -> bytes:
            path = {"source": source, "build": base, "sdk": base.parent / "cache"}[
                root
            ] / local
            for parent in (path, *path.parents):
                remember(parent)
                if parent in (source, base, base.parent / "cache"):
                    break
            return reader.read(root, local, limit)

        lock = tomllib.loads(read("source", "Cargo.lock", MAX_METADATA).decode())
        selected = [
            item
            for item in lock.get("package", [])
            if item.get("source")
            == "registry+https://github.com/rust-lang/crates.io-index"
            and f"{item.get('name')}-{item.get('version')}" == package.name
        ]
        require(len(selected) == 1, "Registry package не выбран frozen Cargo.lock")
        checksum = selected[0].get("checksum")
        require(
            isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum),
            "Registry lock checksum",
        )
        local = package.relative_to(base).as_posix()
        cap = min(MAX_FILE, PROFILE["registry_unpacked_byte_cap"])
        archive = read("sdk", local + ".crate", cap)
        require(
            hashlib.sha256(archive).hexdigest() == checksum,
            "Registry archive checksum mismatch",
        )
        members: set[str] = set()
        total = 0
        with _registry_tar(archive) as tar:
            for index, member in enumerate(tar):
                require(index < MAX_FILES, "Registry archive member cap")
                parts = member.name.split("/")
                require(
                    parts[0] == package.name
                    and ".." not in parts
                    and not member.name.startswith("/"),
                    "Registry archive path",
                )
                if member.isdir():
                    continue
                require(
                    member.isfile()
                    and not member.issparse()
                    and 0 <= member.size <= cap,
                    "Registry archive member type/cap",
                )
                name = relative("/".join(parts[1:]))
                require(name not in members, "Registry duplicate member")
                members.add(name)
                total += member.size
                require(total <= cap, "Registry expanded byte cap")
                stream = tar.extractfile(member)
                require(stream is not None, "Registry archive missing member")
                with stream:
                    expected = stream.read(member.size + 1)
                require(
                    read("build", local + "/" + name, MAX_FILE) == expected,
                    "Registry extracted member mismatch",
                )
        require(bool(members), "Registry empty archive")
        remember(package)
        try:
            yield members
        finally:
            for path, identity in identities.items():
                require(_identity(path) == identity, "Registry input изменился")


def compiler_capture(
    config: dict,
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    runner: Runner = execute,
) -> tuple[int, bytes, bytes]:
    build = Path(config["build"])
    number = _reserve(build)
    dep = build / "p25capture" / f"{number}.d"
    purpose, probe_source = probe_shape(argv, build)
    actual = (
        compile_arguments(argv, dep) if purpose in {"compile", "other"} else list(argv)
    )
    proof = None
    with ExitStack() as stack:
        if not (
            cwd.is_relative_to(Path(config["source"])) or cwd.is_relative_to(build)
        ):
            members = stack.enter_context(registry_package(Path(config["source"]), cwd))
            for arg in argv:
                if not arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++")):
                    continue
                unit = Path(arg) if Path(arg).is_absolute() else cwd / arg
                require(".." not in unit.parts, "Registry unit traversal")
                require(
                    unit.is_relative_to(build)
                    or unit.is_relative_to(Path(config["source"]))
                    or (
                        unit.is_relative_to(cwd)
                        and unit.relative_to(cwd).as_posix() in members
                    ),
                    "Registry unit вне выбранного package/frozen roots",
                )
        if probe_source is not None:
            with ExitStack() as source_stack:
                source_reader = Reader(
                    {
                        "source": Path(config["source"]),
                        "build": build,
                        "sdk": Path(config["sdk"]),
                    },
                    source_stack,
                )
                stamps = {
                    path: _identity(path)
                    if path == Path(probe_source)
                    else _identity(path)[:3]
                    for path in (Path(probe_source), *Path(probe_source).parents)
                    if path == build or path.is_relative_to(build)
                }
                raw = source_reader.read(
                    "build", Path(probe_source).relative_to(build).as_posix(), PROBE_CAP
                )
            digest = hashlib.sha256(raw).hexdigest()
            require(
                raw == FLAG_BODY
                if purpose == "flag-support"
                else digest == FAMILY_HASH,
                "Probe body mismatch",
            )
            proof = {"source": probe_source, "bytes_hex": raw.hex(), "sha256": digest}
        with trusted_tool(PROFILE["compiler"]) as (fd, compiler):
            command = [PROFILE["compiler"], *actual]
            code, out, err = runner(fd, command, cwd, env)
        if probe_source is not None:
            require(
                all(
                    (
                        _identity(path)
                        if path == Path(probe_source)
                        else _identity(path)[:3]
                    )
                    == stamp
                    for path, stamp in stamps.items()
                ),
                "Probe source changed during execution",
            )
    row = {
        "schema": 2,
        "purpose": purpose,
        "probe": proof,
        "config_sha256": env.get("YONIK_P25_CONFIG_SHA256"),
        "argv": command,
        "original_argv": argv,
        "cwd": str(cwd),
        "compiler": compiler,
        "exit": code,
        "stdout_sha256": hashlib.sha256(out).hexdigest(),
        "stderr_sha256": hashlib.sha256(err).hexdigest(),
        "depfile": None,
        "unit": None,
    }
    if purpose == "compile" and code == 0:
        units = [
            arg for arg in argv if arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++"))
        ]
        require(len(units) == 1, "Неоднозначный CXX unit")
        row["unit"] = (
            str(cwd / units[0]) if not Path(units[0]).is_absolute() else units[0]
        )
        row["depfile"] = f"p25capture/{number}.d"
    require(
        len(out) <= PROFILE["stream_cap"] and len(err) <= PROFILE["stream_cap"],
        "Compiler log cap",
    )
    _write(build / "p25capture" / f"{number}.json", row)
    return code, out, err


def prepare(
    source: Path, build: Path, env: dict[str, str], runner: Runner = execute
) -> None:
    """Только внутри будущей build phase. Один observed query, не host audit."""
    build.mkdir(mode=0o700, exist_ok=True)
    (build / "p25capture").mkdir(mode=0o700)
    config = {
        "schema": 1,
        "source": str(source),
        "build": str(build),
        "sdk": PROFILE["sdk_root"],
    }
    pin = _write(build / "p25capture/config.json", config)
    env["YONIK_P25_CONFIG"] = str(build / "p25capture/config.json")
    env["YONIK_P25_CONFIG_SHA256"] = pin
    env["CXX"] = str(source / "tools/p25_cxx_capture_wrapper.py")
    env["CXX_x86_64_unknown_linux_gnu"] = env["CXX"]
    env["CXX_x86_64-unknown-linux-gnu"] = env["CXX"]
    env["TARGET_CXX"] = env["CXX"]
    with trusted_tool(PROFILE["qt_query"][0]) as (fd, tool):
        code, out, err = runner(fd, list(PROFILE["qt_query"]), source, env)
    require(
        len(out) <= PROFILE["stream_cap"] and len(err) <= PROFILE["stream_cap"],
        "Qt query log cap",
    )
    version = out.decode("ascii").strip()
    require(
        code == 0 and re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
        "Неуспешный fixed Qt query",
    )
    _write(
        build / "p25capture/qt-observed.json",
        {
            "schema": 1,
            "query_argv": PROFILE["qt_query"],
            "version": version,
            "exit": code,
            "tool": tool,
            "stdout": out.decode("ascii"),
            "stderr_sha256": hashlib.sha256(err).hexdigest(),
        },
    )


def wrapper_config(env: dict[str, str]) -> dict:
    path = Path(env["YONIK_P25_CONFIG"])
    parent = _directory(path.parent)
    try:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Config не regular")
        raw = stream.read(MAX_METADATA + 1)
    require(
        len(raw) <= MAX_METADATA
        and hashlib.sha256(raw).hexdigest() == env["YONIK_P25_CONFIG_SHA256"],
        "Config pin mismatch/cap",
    )
    config = parse(raw)
    require(
        set(config) == {"schema", "source", "build", "sdk"} and config["schema"] == 1,
        "Неверный config",
    )
    require(
        config["sdk"] == PROFILE["sdk_root"]
        and path == Path(config["build"]) / "p25capture/config.json",
        "Config root mismatch",
    )
    with ExitStack() as stack:
        Reader({key: Path(config[key]) for key in ("source", "build", "sdk")}, stack)
    return config


def enrich(roots: dict[str, Path], record: dict, retained: Path) -> dict:
    """Закрытый join собственных wrapper records; inventory SDK не сканируется."""
    from p25_capture_build_closure import MAX_GENERATED, MAX_TEXT

    observed: list[dict] = []
    missing: list[str] = []
    rows = record["files"]
    known = {(row["root"], row["path"]): row for row in rows}
    origins: dict[str, str] = {}
    compiled_units: set[str] = set()
    aliases: dict[str, dict] = {}
    with ExitStack() as stack:
        reader = Reader(roots, stack)
        external_readers: dict[str, Reader] = {}
        registry_members: dict[Path, set[str]] = {}

        def stage(absolute: Path, kind: str) -> str:
            origin = str(absolute)
            if origin in origins:
                return origins[origin]
            allowed = [Path(PROFILE["sdk_root"]), Path(PROFILE["registry_source_root"])]
            matches = [root for root in allowed if absolute.is_relative_to(root)]
            require(len(matches) == 1, f"Dependency вне fixed input roots: {absolute}")
            base = matches[0]
            if base == Path(PROFILE["registry_source_root"]):
                parts = absolute.relative_to(base).parts
                require(len(parts) >= 3, "Registry input не package member")
                package = base / parts[0] / parts[1]
                if package not in registry_members:
                    registry_members[package] = stack.enter_context(
                        registry_package(roots["source"], package)
                    )
                require(
                    "/".join(parts[2:]) in registry_members[package],
                    "Registry input вне archive members",
                )
            key = str(base)
            if key not in external_readers:
                external_readers[key] = Reader(
                    {"source": roots["source"], "build": roots["build"], "sdk": base},
                    stack,
                )
            external = external_readers[key]
            limit = MAX_FILE if kind == "tool" else MAX_TEXT
            local = relative(absolute.relative_to(base).as_posix())
            # Reader проверяет ancestors/type/stat/caps до сохранения точных bytes.
            _, expected = external._consume("sdk", local, limit, False)
            require(
                sum(item.total for item in external_readers.values())
                <= 1024 * 1024 * 1024,
                "External input total cap",
            )
            name = hashlib.sha256(origin.encode()).hexdigest()
            parent = _directory(absolute.parent)
            try:
                incoming = os.open(
                    absolute.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
            finally:
                os.close(parent)
            with os.fdopen(incoming, "rb") as stream:
                before = os.fstat(stream.fileno())
                require(
                    stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                    "Staging type/cap",
                )
                directory = _directory(roots["sdk"])
                try:
                    fd = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    with os.fdopen(fd, "wb") as output:
                        checksum = hashlib.sha256()
                        size = 0
                        while chunk := stream.read(65536):
                            size += len(chunk)
                            require(size <= limit, "Staging byte cap")
                            checksum.update(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    os.fsync(directory)
                finally:
                    os.close(directory)
                after = os.fstat(stream.fileno())
                require(
                    checksum.hexdigest() == expected
                    and size == before.st_size
                    and (
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    == (
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ),
                    "Staging changed input",
                )
            origins[origin] = name
            return name

        def add(
            path: str, cwd: Path, kind: str | None = None, expected: str | None = None
        ) -> str:
            original = Path(path) if Path(path).is_absolute() else cwd / path
            absolute = Path(os.path.normpath(original))
            if ".." in original.parts:
                # Проверяем пропускаемые normalization ancestors до hash, чтобы
                # symlink/../ не подменил фактически прочитанный compiler input.
                require(
                    not set(original.parts)
                    & {".ssh", ".gnupg", ".config", ".aws", ".env"},
                    "Private dependency path",
                )
                directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
                try:
                    for part in original.parts[1:-1]:
                        nested = os.open(
                            part,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory,
                        )
                        os.close(directory)
                        directory = nested
                    canonical = _directory(absolute.parent)
                    try:
                        actual_stat, canonical_stat = (
                            os.fstat(directory),
                            os.fstat(canonical),
                        )
                        require(
                            (actual_stat.st_dev, actual_stat.st_ino)
                            == (canonical_stat.st_dev, canonical_stat.st_ino),
                            "Ambiguous dependency parent",
                        )
                    finally:
                        os.close(canonical)
                finally:
                    os.close(directory)
            alias_origin = None
            alias_links = []
            if forest(absolute, roots["build"]):
                canonical, alias_links = alias_target(absolute, roots["build"], stack)
                if alias_links:
                    alias_origin = str(absolute)
                    absolute = canonical
            matches = [
                (name, root)
                for name, root in roots.items()
                if absolute.is_relative_to(root)
            ]
            origin = str(absolute)
            if not matches:
                inferred_kind = kind or (
                    "sdk-unit" if origin in compiled_units else "header"
                )
                staged = stage(absolute, inferred_kind)
                absolute = roots["sdk"] / staged
                matches = [("sdk", roots["sdk"])]
                kind = inferred_kind
            require(len(matches) == 1, f"Input вне roots: {absolute}")
            root, base = matches[0]
            local = relative(absolute.relative_to(base).as_posix())
            key = (root, local)
            if alias_origin is not None:
                _, checksum = reader._consume(root, local, MAX_GENERATED, False)
                require(
                    len(aliases) < ALIAS_CAP or alias_origin in aliases, "Alias map cap"
                )
                aliases[alias_origin] = {
                    "canonical": str(absolute),
                    "links": alias_links,
                    "sha256": checksum,
                }
            if key in known:
                row = known[key]
                if origin in compiled_units and row["kind"] == "header":
                    row["kind"] = "sdk-unit"
                require(
                    expected is None or row["sha256"] == expected,
                    "Изменён observed input",
                )
                return row["id"]
            actual_kind = (
                kind
                or {"source": "source", "build": "generated", "sdk": "header"}[root]
            )
            limit = (
                MAX_FILE
                if actual_kind == "tool"
                else MAX_GENERATED
                if actual_kind == "generated"
                else MAX_TEXT
            )
            _, checksum = reader._consume(root, local, limit, False)
            require(
                expected is None or checksum == expected, "Observed tool hash mismatch"
            )
            require(len(rows) < MAX_FILES, "File whitelist cap")
            row = {
                "id": f"input-{len(rows)}",
                "root": root,
                "path": local,
                "kind": actual_kind,
                "sha256": checksum,
            }
            rows.append(row)
            known[key] = row
            return row["id"]

        try:
            count = int(reader.read("build", "p25capture/count", 16))
        except FileNotFoundError:
            count = 0
        require(0 <= count <= MAX_FILES, "Wrapper invocation count cap")
        config_raw = reader.read("build", "p25capture/config.json", MAX_METADATA)
        config_pin = hashlib.sha256(config_raw).hexdigest()
        metadata_bytes = len(config_raw)
        dependency_rows = 0
        for number in range(count):
            raw = reader.read("build", f"p25capture/{number}.json", MAX_METADATA)
            metadata_bytes += len(raw)
            require(
                metadata_bytes <= PROFILE["observed_metadata_cap"],
                "Observed metadata total cap",
            )
            row = parse(raw)
            fields = {
                "schema",
                "config_sha256",
                "argv",
                "original_argv",
                "cwd",
                "compiler",
                "exit",
                "depfile",
                "unit",
                "stdout_sha256",
                "stderr_sha256",
            }
            if row.get("schema") == 2:
                fields |= {"purpose", "probe"}
            object_fields(row, fields, fields)
            require(row["config_sha256"] == config_pin, "Observed config pin mismatch")
            is_probe = validate_purpose(row, roots["build"])
            object_fields(row["compiler"], {"path", "sha256"}, {"path", "sha256"})
            require(
                row["argv"]
                == [
                    PROFILE["compiler"],
                    *(
                        row["original_argv"]
                        if is_probe
                        else compile_arguments(
                            row["original_argv"],
                            roots["build"] / "p25capture" / f"{number}.d",
                        )
                    ),
                ],
                "Observed argv binding mismatch",
            )
            if is_probe or "-c" not in row["original_argv"]:
                require(
                    row["unit"] is None and row["depfile"] is None,
                    "Probe не compile record",
                )
            else:
                units = [
                    arg
                    for arg in row["original_argv"]
                    if arg.endswith((".cpp", ".cxx", ".cc", ".C", ".c++"))
                ]
                require(
                    len(units) == 1 and row["unit"] == str(Path(row["cwd"]) / units[0]),
                    "Observed unit binding mismatch",
                )
            cwd = Path(row["cwd"])
            if not (
                cwd.is_relative_to(roots["source"])
                or cwd.is_relative_to(roots["build"])
            ):
                if cwd not in registry_members:
                    registry_members[cwd] = stack.enter_context(
                        registry_package(roots["source"], cwd)
                    )
            compiler_id = add(
                row["compiler"]["path"], roots["sdk"], "tool", row["compiler"]["sha256"]
            )
            observed.append({**row, "compiler_id": compiler_id})
            if row["unit"] is None:
                continue
            require(
                row["depfile"] == f"p25capture/{number}.d", "Depfile binding mismatch"
            )
            cwd = Path(row["cwd"])
            compiled_units.add(os.path.normpath(row["unit"]))
            unit = add(row["unit"], cwd)
            raw_dep = reader.read("build", row["depfile"], MAX_METADATA)
            dep_paths = dependencies(raw_dep)
            dependency_rows += len(dep_paths)
            require(
                dependency_rows <= PROFILE["dependency_row_cap"], "Dependency rows cap"
            )
            deps = [add(path, cwd) for path in dep_paths]
            require(unit in deps, "Depfile не содержит actual unit")
            dep_path = f"p25capture/{number}-normalized.json"
            normalized = {
                "schema": 1,
                "unit": unit,
                "dependencies": list(dict.fromkeys(deps)),
            }
            dep_hash = _write(roots["build"] / dep_path, normalized)
            dep_id = add(str(roots["build"] / dep_path), cwd, "depfile", dep_hash)
            record["units"].append(
                {"file": unit, "depfile": dep_id, "argv": row["argv"]}
            )
            observed[-1]["raw_depfile_sha256"] = hashlib.sha256(raw_dep).hexdigest()
            observed[-1]["normalized_depfile"] = normalized
        qt = parse(reader.read("build", "p25capture/qt-observed.json", MAX_METADATA))
        require(
            qt["query_argv"] == PROFILE["qt_query"]
            and qt["exit"] == 0
            and re.fullmatch(r"\d+\.\d+\.\d+", qt["version"]) is not None,
            "Неверный observed fixed Qt query",
        )
        query_tool = add(qt["tool"]["path"], roots["sdk"], "tool", qt["tool"]["sha256"])
        qt_normalized = {
            "schema": 1,
            "version": qt["version"],
            "sdk_files": [row["id"] for row in rows if row["root"] == "sdk"],
            "query_argv": qt["query_argv"],
            "query_tool": query_tool,
            "exit": 0,
        }
        qt_path = roots["build"] / "p25capture/qt-normalized.json"
        qt_hash = _write(qt_path, qt_normalized)
        record["qt_version"] = add(str(qt_path), roots["build"], "qt-version", qt_hash)
        record["source"]["tracked_inputs"] = [
            row["id"] for row in rows if row["root"] == "source"
        ]
    missing.append("qt:query-to-header-version-join")
    if not record["units"]:
        missing.append("cxx:invocations")
    for row in rows:
        if row["kind"] == "generated":
            missing.append(f"generation-provenance:{row['id']}")
        if row["kind"] in ("header", "sdk-unit"):
            missing.append(f"source-offer-primary-join:{row['id']}")
    observed_hash = _write(
        retained / "build-cxx-observed.json",
        {
            "schema": 2,
            "aliases": aliases,
            "records": observed,
            "qt": qt,
            "input_origins": origins,
            "config": parse(config_raw),
            "config_sha256": config_pin,
        },
        PROFILE["observed_metadata_cap"],
    )
    return {
        "producer_missing": missing,
        "compiled_units": len(record["units"]),
        "observed_invocations": len(observed),
        "qt_version": qt["version"],
        "observed_sha256": observed_hash,
    }
