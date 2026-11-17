"""Закреплённые сборки sing-box и Xray без изменения зарегистрированных pins."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

SOURCE_URL = "https://github.com/SagerNet/sing-box.git"
SOURCE_TAG = "v1.14.4"
SOURCE_VERSION = SOURCE_TAG.removeprefix("v")
SOURCE_COMMIT = "c005f35300ce76427dc285481ec5695f5b179cd2"
TRANSIENT = Path("/var/tmp/codex-myrs/transient")
DEFAULT_ROOT = TRANSIENT / "yonik-native-adapter"
DEFAULT_PATCH = (
    Path(__file__).resolve().parents[1]
    / "adapters/sing-box/v1.14.4/strict-complete-dns.patch"
)
EXTRA_PATCHES = (
    (DEFAULT_PATCH.with_name("resolution-provenance.patch"), "dns_provenance"),
    (DEFAULT_PATCH.with_name("resolution-pin.patch"), "pin_resolution"),
    (
        DEFAULT_PATCH.with_name("external-tun-configuration.patch"),
        "external_tun_configuration",
    ),
)
XRAY_URL = "https://github.com/XTLS/Xray-core.git"
XRAY_TAG = "v26.10.31"
XRAY_COMMIT = "a4a3dff5b20c2faae567b742c172c7b95e75c083"
PROFILE_PATCH = "3c156ca03b36d22d94a5f8cadfd42705a80833f45f65c17cb210fe6a2705b3ec"
LOG = logging.getLogger("yonik.native_adapter")
COMMAND_TIMEOUT = 180
BUILD_TIMEOUT = 900


def dns_release_candidate(record: dict[str, object]) -> dict[str, object]:
    """Compile-only запрос review; protected install authority здесь не создаётся."""
    candidate = dict(record)
    candidate["dns_release"] = {
        "contract": "direct-dns-consuming-close-join-v1",
        "version": 1,
        "contract_sha256": hashlib.sha256(
            b"direct-dns-consuming-close-join-v1\0"
        ).hexdigest(),
        "schema_sha256": hashlib.sha256(b"YONIK-DNS-V2-CODEC-3\0").hexdigest(),
    }
    candidate["dns_wire"] = {
        "contract": "direct-dns-bound-request-response-v1",
        "version": 1,
        "contract_sha256": hashlib.sha256(
            b"direct-dns-bound-request-response-v1\0"
        ).hexdigest(),
        "schema_sha256": hashlib.sha256(b"YONIK-DNS-V2-CODEC-3\0").hexdigest(),
    }
    return {
        "validation": "COMPILE_ONLY_CANDIDATE",
        "install_authority": False,
        "requires_factory_ownership_review": True,
        "candidate_record": candidate,
    }


def bootstrap_candidate(record: dict[str, object]) -> dict[str, object]:
    """Три независимых review-запроса; это не protected install record."""
    candidate = dict(record)
    for slot, contract in (
        ("bootstrap_source", "captured-netgo-bootstrap-parent-member-v1"),
        ("bootstrap_dns_wire", "bootstrap-direct-dns-bound-request-response-v1"),
        ("bootstrap_dns_release", "bootstrap-direct-dns-consuming-close-join-v1"),
    ):
        candidate[slot] = {
            "contract": contract,
            "version": 1,
            "contract_sha256": hashlib.sha256(contract.encode() + b"\0").hexdigest(),
            "schema_sha256": hashlib.sha256(b"YONIK-DNS-V2-CODEC-4\0").hexdigest(),
        }
    return {
        "validation": "COMPILE_ONLY_CANDIDATE",
        "install_authority": False,
        "requires_independent_scope_review": True,
        "subset": "single_raw_tcp_branch0",
        "candidate_record": candidate,
    }


class BuildError(RuntimeError):
    """Сборка остановлена; оставленные исходники и логи требуют проверки."""


def build_arguments(
    binary: Path, tags: list[str], engine: str = "sing-box"
) -> list[str]:
    if engine == "xray":
        return [
            "go",
            "build",
            "-p=1",
            "-mod=readonly",
            "-trimpath",
            "-buildvcs=false",
            "-o",
            str(binary),
            "./main",
        ]
    if engine != "sing-box":
        raise BuildError("Неизвестное ядро")
    return [
        "go",
        "build",
        "-p=1",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags",
        f"-X github.com/sagernet/sing-box/constant.Version={SOURCE_VERSION}",
        "-tags",
        ",".join(tags),
        "-o",
        str(binary),
        "./cmd/sing-box",
    ]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def toolchain_digest(runner: Runner, source: Path) -> str:
    """Hash actual local driver/compile/link, не строки go version."""
    executable = shutil.which("go", path=runner.env.get("PATH"))
    if executable is None:
        raise BuildError("Local Go toolchain отсутствует")
    directory = Path(runner.run(["go", "env", "GOTOOLDIR"], source).strip())
    files = [Path(executable).resolve(), directory / "compile", directory / "link"]
    return hashlib.sha256(
        "\n".join(sha256(path) for path in files).encode()
    ).hexdigest()


def source_digest(source: Path) -> str:
    entries = []
    for directory, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in [*dirs, *sorted(files)]:
            path = Path(directory) / name
            if path.is_symlink():
                raise BuildError("Experimental source не допускает symlink")
            if path.is_file():
                entries.append((str(path.relative_to(source)), sha256(path)))
    return hashlib.sha256(
        json.dumps(entries, separators=(",", ":")).encode()
    ).hexdigest()


class Runner:
    """Команды без shell, с отдельными stdout/stderr и локальным Go cache."""

    def __init__(self, root: Path) -> None:
        self.logs = root / "build-native-adapter-logs"
        try:
            self.logs.mkdir()
        except FileExistsError as error:
            raise BuildError(
                f"Обнаружен предыдущий запуск: {self.logs}; проверьте его вручную"
            ) from error
        self.sequence = 0
        # GOFLAGS, GOENV, GOCACHEPROG и прочие внешние настройки не должны
        # незаметно менять закреплённую команду или запускать сторонний код.
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GO") or key in {"GOOS", "GOARCH", "GOEXPERIMENT"}
        }
        cache = root / "build-native-adapter-cache"
        for variable, name in {
            "GOCACHE": "go-build",
            "GOMODCACHE": "go-mod",
            "GOPATH": "gopath",
            "GOTMPDIR": "go-tmp",
            "TMPDIR": "tmp",
            "XDG_CACHE_HOME": "xdg-cache",
            "XDG_CONFIG_HOME": "xdg-config",
        }.items():
            directory = cache / name
            directory.mkdir(parents=True, exist_ok=True)
            self.env[variable] = str(directory)
        self.env.update(
            GOTOOLCHAIN="local",
            GOENV="off",
            GOWORK="off",
            CGO_ENABLED="0",
            GOMAXPROCS="1",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0",
        )

    def run(self, argv: list[str], cwd: Path) -> str:
        self.sequence += 1
        prefix = self.logs / f"{self.sequence:02d}-{Path(argv[0]).name}"
        prefix.with_suffix(".command.json").write_text(
            json.dumps({"argv": argv, "cwd": str(cwd)}, ensure_ascii=False) + "\n"
        )
        stdout = prefix.with_suffix(".stdout.log")
        stderr = prefix.with_suffix(".stderr.log")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            pending: list[int] = []
            signals = (signal.SIGINT, signal.SIGTERM)
            previous = {event: signal.getsignal(event) for event in signals}
            process: subprocess.Popen[bytes] | None = None
            try:
                try:
                    # Не теряем handle, если сигнал пришёл во время Popen.
                    for event in signals:
                        signal.signal(
                            event, lambda signum, _frame: pending.append(signum)
                        )
                    process = subprocess.Popen(
                        argv,
                        cwd=cwd,
                        env=self.env,
                        stdout=out,
                        stderr=err,
                        stdin=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                finally:
                    for event, handler in previous.items():
                        signal.signal(event, handler)
                if pending:
                    raise SystemExit(128 + pending[0])
                try:
                    code = process.wait(
                        timeout=BUILD_TIMEOUT
                        if argv[:2] == ["go", "build"]
                        else COMMAND_TIMEOUT
                    )
                except subprocess.TimeoutExpired as error:
                    raise BuildError(
                        f"{argv[0]} превысил лимит времени; логи: {prefix}.*"
                    ) from error
            finally:
                # Cleanup охватывает и восстановление handlers после Popen.
                for event in signals:
                    signal.signal(event, lambda _signum, _frame: None)
                try:
                    if process is not None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                finally:
                    for event, handler in previous.items():
                        signal.signal(event, handler)
        if code:
            raise BuildError(f"{argv[0]} завершился с кодом {code}; логи: {prefix}.*")
        return stdout.read_text(errors="replace")


def build(
    root: Path,
    output: Path,
    patch: Path,
    engine: str = "sing-box",
    *,
    native_codec: bool = False,
    compile_only: bool = False,
    experimental_profile: bool = False,
) -> Path:
    """Собрать один раз; повторный запуск не сбрасывает частичные результаты."""
    if engine not in {"sing-box", "xray"}:
        raise BuildError("Неизвестное ядро")
    if experimental_profile and (engine != "xray" or not compile_only):
        raise BuildError("Experimental profile требует Xray compile-only")
    root = root.resolve()
    output = output.resolve()
    patch = patch.resolve(strict=True)
    if engine == "sing-box" and sha256(patch) != sha256(DEFAULT_PATCH):
        raise BuildError("Требуется канонический strict_complete_dns patch")
    if output.is_relative_to(root) or output.is_relative_to(TRANSIENT):
        raise BuildError("--output-dir должен быть вне transient/build root")
    if any(
        (output / name).exists() for name in (engine, "manifest.json", "prebuild.json")
    ):
        raise BuildError(
            "В --output-dir уже есть binary/manifest; перезапись запрещена"
        )
    root.mkdir(parents=True, exist_ok=True)
    # Lock именно inode корня защищает всё дерево от TTL cleaner. Shared lock
    # совместим с исследованием в других подкаталогах этого task root.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        return build_locked(
            root,
            output,
            patch,
            engine,
            native_codec=native_codec,
            compile_only=compile_only,
            experimental_profile=experimental_profile,
        )
    finally:
        os.close(descriptor)


def build_locked(
    root: Path,
    output: Path,
    patch: Path,
    engine: str = "sing-box",
    *,
    native_codec: bool = False,
    compile_only: bool = False,
    experimental_profile: bool = False,
) -> Path:
    source_url, source_tag, source_commit = (
        (XRAY_URL, XRAY_TAG, XRAY_COMMIT)
        if engine == "xray"
        else (SOURCE_URL, SOURCE_TAG, SOURCE_COMMIT)
    )
    source_version = source_tag.removeprefix("v")
    runner = Runner(root)
    if experimental_profile:
        runner.env = {
            key: value
            for key, value in runner.env.items()
            if not key.startswith(("GIT_", "LD_", "DYLD_"))
            and key not in {"ENV", "BASH_ENV"}
        }
        runner.env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0",
            GIT_WORK_TREE=str(root / "build-source-xray"),
            GIT_CONFIG_COUNT="2",
            GIT_CONFIG_KEY_0="core.fsmonitor",
            GIT_CONFIG_VALUE_0="false",
            GIT_CONFIG_KEY_1="core.hooksPath",
            GIT_CONFIG_VALUE_1=os.devnull,
        )
    if compile_only:
        runner.env.update(GOPROXY="off", GOSUMDB="off")
    source = root / f"build-source-{engine}"
    if source.is_symlink():
        raise BuildError(f"Исходник не должен быть symlink: {source}")
    if not source.exists():
        if experimental_profile:
            raise BuildError(
                "Experimental profile требует подготовленный offline source"
            )
        runner.run(
            [
                "git",
                "clone",
                "--depth=1",
                "--branch",
                source_tag,
                "--",
                source_url,
                str(source),
            ],
            root,
        )
    head = runner.run(["git", "rev-parse", "HEAD"], source).strip()
    tag = runner.run(["git", "rev-parse", f"{source_tag}^{{commit}}"], source).strip()
    if head != source_commit or tag != source_commit:
        raise BuildError(f"Неверный HEAD/tag: ожидался {source_commit}, HEAD={head}")
    dirty = runner.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--ignored"], source
    )
    if dirty.strip():
        raise BuildError(f"Исходник должен быть чистым: {source}")
    modules = {name: sha256(source / name) for name in ("go.mod", "go.sum")}
    patches = (
        [(patch, "strict_complete_dns"), *EXTRA_PATCHES] if engine == "sing-box" else []
    )
    patch_records = []
    for index, (path, feature) in enumerate(patches):
        path = path.resolve(strict=True)
        digest = sha256(path)
        runner.run(["git", "apply", "--check", str(path)], source)
        runner.run(["git", "apply", str(path)], source)
        if sha256(path) != digest:
            raise BuildError("Патч изменился во время применения")
        if modules != {name: sha256(source / name) for name in modules}:
            raise BuildError("Патч изменяет go.mod/go.sum")
        patch_records.append(
            {
                "name": DEFAULT_PATCH.name if index == 0 else path.name,
                "sha256": digest,
                "feature": feature,
            }
        )
    codec_record = None
    if native_codec or experimental_profile:
        version = XRAY_TAG if engine == "xray" else SOURCE_TAG
        codec_patch = (
            DEFAULT_PATCH.parents[2] / engine / version / "native-broker-codec.patch"
        )
        metadata = json.loads(codec_patch.with_suffix(".json").read_text())
        digest = sha256(codec_patch)
        if digest != metadata["patch_sha256"] or metadata["runtime_hooks_connected"]:
            raise BuildError("Некорректный component codec manifest")
        runner.run(["git", "apply", "--check", str(codec_patch)], source)
        runner.run(["git", "apply", str(codec_patch)], source)
        package = source / "common/yonikbroker"
        for name, expected in metadata["package_files_sha256"].items():
            if sha256(package / name) != expected:
                raise BuildError(f"Codec hash mismatch: {name}")
        for name, expected in metadata.get("callsite_files_sha256", {}).items():
            if sha256(source / name) != expected:
                raise BuildError(f"Callsite hash mismatch: {name}")

        def check_package(package: str) -> None:
            arguments = ["go", "test", "-p=1", "-mod=readonly"]
            if compile_only:
                test_binary = root / (
                    package.removeprefix("./").replace("/", "-") + ".test"
                )
                arguments.extend(["-c", "-o", str(test_binary)])
            runner.run([*arguments, package], source)

        check_package("./common/yonikbroker")
        if metadata.get("routing_entry_guard_connected"):
            check_package("./app/dispatcher" if engine == "xray" else "./route")
        if metadata.get("owned_tun_constructor_connected"):
            check_package("./proxy/tun" if engine == "xray" else "./protocol/tun")
        if modules != {name: sha256(source / name) for name in modules}:
            raise BuildError("Codec изменил go.mod/go.sum")
        codec_record = {
            "patch_sha256": digest,
            "runtime_hooks_connected": False,
            "owned_tun_constructor_connected": metadata.get(
                "owned_tun_constructor_connected", False
            ),
            "frozen_spec_commit": metadata["frozen_spec_commit"],
            "routing_entry_guard_connected": metadata.get(
                "routing_entry_guard_connected", False
            ),
            "callsite_files_sha256": metadata.get("callsite_files_sha256", {}),
        }
    profile_metadata = None
    if experimental_profile:
        profile_patch = (
            DEFAULT_PATCH.parents[2] / "xray" / XRAY_TAG / "native-full-profile.patch"
        )
        profile_metadata = json.loads(profile_patch.with_suffix(".json").read_text())
        if (
            sha256(profile_patch) != PROFILE_PATCH
            or profile_metadata["patch_sha256"] != PROFILE_PATCH
            or profile_metadata["source_commit"] != XRAY_COMMIT
        ):
            raise BuildError(
                "Неодобренный full-profile patchset; требуется root source review"
            )
        runner.run(["git", "apply", "--check", str(profile_patch)], source)
        runner.run(["git", "apply", str(profile_patch)], source)
        for name, expected in {
            **{
                f"common/yonikbroker/{name}": value
                for name, value in profile_metadata["package_files_sha256"].items()
            },
            **profile_metadata["callsite_files_sha256"],
        }.items():
            if sha256(source / name) != expected:
                raise BuildError(f"Full-profile source pin mismatch: {name}")
        if modules != {name: sha256(source / name) for name in modules}:
            raise BuildError("Full-profile изменил go.mod/go.sum")
        patch_records.append(
            {
                "name": profile_patch.name,
                "sha256": PROFILE_PATCH,
                "feature": "experimental_profile",
            }
        )
    raw_tags = (
        (source / "release/DEFAULT_BUILD_TAGS_OTHERS").read_text().strip()
        if engine == "sing-box"
        else ""
    )
    tags = re.split(r"[,\s]+", raw_tags) if raw_tags else []
    if engine == "sing-box" and (
        not raw_tags or any(not re.fullmatch(r"[A-Za-z0-9_]+", tag) for tag in tags)
    ):
        raise BuildError("Некорректные upstream build tags")
    go_version = runner.run(["go", "version"], source).strip()
    compiler_digest = toolchain_digest(runner, source) if experimental_profile else None
    go_env = json.loads(
        runner.run(["go", "env", "-json", "GOOS", "GOARCH", "GOEXPERIMENT"], source)
    )
    binary = root / f"build-native-adapter-{engine}"
    if binary.exists() or binary.is_symlink():
        raise BuildError(f"Обнаружен предыдущий бинарник: {binary}")
    args = build_arguments(binary, tags, engine)
    tree_digest = source_digest(source) if experimental_profile else None
    prebuild = {
        "builder_sha256": sha256(Path(__file__)),
        "engine": engine,
        "source_url": source_url,
        "source_tag": source_tag,
        "source_commit": head,
        "patches": patch_records,
        "module_sha256": modules,
        "go_version": go_version,
        "toolchain_sha256": compiler_digest,
        "source_tree_sha256": tree_digest,
        "go_env": go_env,
        "build_args": args,
        "build_environment": {
            key: runner.env[key]
            for key in ("GOTOOLCHAIN", "GOENV", "GOWORK", "CGO_ENABLED", "GOMAXPROCS")
        },
        "native_protocol": None,
        "native_codec_component": codec_record,
        "validation": "COMPILE_ONLY" if compile_only else "BUILD_AND_VERSION",
    }
    (runner.logs / "prebuild.json").write_text(
        json.dumps(prebuild, ensure_ascii=False, indent=2) + "\n"
    )
    try:
        runner.run(args, source)
    finally:
        if modules != {name: sha256(source / name) for name in modules}:
            raise BuildError("go.mod/go.sum изменились при сборке")
    if any(
        sha256(path) != record["sha256"]
        for (path, _), record in zip(
            patches, patch_records[: len(patches)], strict=True
        )
    ):
        raise BuildError("Патч изменился во время сборки")
    if not binary.is_file() or binary.is_symlink():
        raise BuildError("Go не создал ожидаемый бинарник")
    if experimental_profile and sha256(profile_patch) != PROFILE_PATCH:
        raise BuildError("Full-profile patch изменился во время сборки")
    if experimental_profile and toolchain_digest(runner, source) != compiler_digest:
        raise BuildError("Local Go toolchain изменился при сборке")
    if experimental_profile and source_digest(source) != tree_digest:
        raise BuildError("Full source tree изменился при сборке")
    if experimental_profile:
        with binary.open("rb") as stream:
            if stream.read(4) != b"\x7fELF" or go_env["GOOS"] != "linux":
                raise BuildError("Producer record требует Linux ELF")
    if experimental_profile:
        for name, expected in {
            **{
                f"common/yonikbroker/{name}": value
                for name, value in profile_metadata["package_files_sha256"].items()
            },
            **profile_metadata["callsite_files_sha256"],
        }.items():
            if sha256(source / name) != expected:
                raise BuildError(f"Full-profile source изменился при сборке: {name}")
    if not compile_only:
        version = runner.run([str(binary), "version"], source).splitlines()
        if not version or (
            version[0].strip() != f"sing-box version {source_version}"
            if engine == "sing-box"
            else not version[0].startswith(f"Xray {source_version} (")
        ):
            raise BuildError("Бинарник не подтверждает закреплённую версию ядра")
    manifest = {
        "validation": "COMPILE_ONLY" if compile_only else "BUILD_AND_VERSION",
        "binary_version_executed": not compile_only,
        "prebuild_sha256": sha256(runner.logs / "prebuild.json"),
        "native_protocol": None,
        "native_codec_component": codec_record,
        "engine": engine,
        "engine_version": source_version,
        "source_url": source_url,
        "source_tag": source_tag,
        "source_commit": head,
        "patch_sha256": patch_records[0]["sha256"] if patch_records else None,
        "patches": patch_records,
        "binary_sha256": sha256(binary),
        "go_version": go_version,
        "go_env": go_env,
        "build_environment": {
            key: runner.env[key]
            for key in ("GOTOOLCHAIN", "GOENV", "GOWORK", "CGO_ENABLED", "GOMAXPROCS")
        },
        "build_tags": tags,
        "build_args": args,
        "module_sha256": modules,
        "adapter_features": {feature: True for _, feature in patches},
        "strictDNSGate": False,
        "strict_dns_gate": False,
        "bit_reproducibility_verified": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    if experimental_profile:
        record = {
            "contract": "yonik-xray-profile-udp-v2",
            "version": 1,
            "source_commit": head,
            "source_sha256": tree_digest,
            "patch_sha256": PROFILE_PATCH,
            "builder_sha256": prebuild["builder_sha256"],
            "toolchain_sha256": compiler_digest,
            "build_inputs_sha256": manifest["prebuild_sha256"],
            "elf_sha256": manifest["binary_sha256"],
        }
        with (output / "native-profile-producer.json").open("x") as stream:
            stream.write(json.dumps(record, indent=2) + "\n")
        with (output / "native-profile-dns-release-candidate.json").open("x") as stream:
            stream.write(json.dumps(dns_release_candidate(record), indent=2) + "\n")
        with (output / "native-profile-bootstrap-candidate.json").open("x") as stream:
            stream.write(json.dumps(bootstrap_candidate(record), indent=2) + "\n")
    destination = output / engine
    with binary.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing)
    destination.chmod(0o755)
    if sha256(destination) != manifest["binary_sha256"]:
        raise BuildError("SHA256 опубликованного бинарника не совпал")
    with (output / "prebuild.json").open("xb") as stream:
        stream.write((runner.logs / "prebuild.json").read_bytes())
    manifest_path = output / "manifest.json"
    with manifest_path.open("x") as stream:
        stream.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("sing-box", "xray"), default="sing-box")
    parser.add_argument(
        "--experimental-profile",
        action="store_true",
        help="Compile-only evidence без установки и runtime readiness",
    )
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="Собрать и сохранить ELF без его исполнения",
    )
    parser.add_argument(
        "--native-codec",
        action="store_true",
        help="Проверить component codec без runtime featureack",
    )
    parser.add_argument("--build-root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    def terminate(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    try:
        manifest = build(
            options.build_root,
            options.output_dir,
            options.patch,
            options.engine,
            native_codec=options.native_codec,
            compile_only=options.compile_only,
            experimental_profile=options.experimental_profile,
        )
    except (BuildError, OSError, ValueError) as error:
        LOG.error("Сборка остановлена: %s", error)
        return 1
    LOG.info("Бинарник и manifest сохранены: %s", manifest.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
