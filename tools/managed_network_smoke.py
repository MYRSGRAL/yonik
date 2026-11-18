"""Запуск реальных managed-network Rust-тестов только в отдельной Linux-сети."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from engine_smoke import install_signal_handlers, run_sandbox

LOG = logging.getLogger("yonik.managed-network")
CASES = {
    "trusted-tools": "managed_network::executable::tests::root_owned_search_accepts_sbin_and_rejects_untrusted_bin",
    "session-attach": "helper::protection_host::session_host::tests::real_namespace_persistent_tun_queue_contract",
    "tun-projection": "managed_network::tun::topology::tests::real_namespace_projection_matches_external_baseline",
    "session-network": "managed_network::tun::topology::tests::real_namespace_session_plan_configure_capture_verify_cleanup",
    "owned-tun": "managed_network::tun::tests::real_namespace_tun_ownership_reopen_and_cleanup",
    "tun-config": "managed_network::tun::config::tests::real_namespace_owned_addresses_routes_and_cleanup",
    "tun-rule": "managed_network::tun::rule::tests::real_namespace_owned_rpdb_and_cleanup",
    "unsupported-tun": "managed_network::tun::session_tests::unpatched_engine_is_rejected_before_network_effects",
    "compiled-tun": "managed_network::tun::session_tests::compiled_profile_crosses_owned_tun_and_proxy",
    "worker-tun": "managed_network::tun::session_tests::compiled_worker_crosses_owned_tun_and_proxy",
    "worker-process": "worker::tests::canonical_worker_process_check_and_run",
    "public-block": "managed_network::nft::block::tests::real_public_block_tcp_udp_dual_stack_and_lifetime",
    "durable-policy": "managed_network::nft::policy::tests::sigkill_recovery_preserves_desired_previous_and_unlock_intents",
    "service": "helper::protection_host::tests::isolated_service_applies_preserves_and_unlocks_real_rules",
}
_BOOTSTRAP = """
import json, os, subprocess, sys
from pathlib import Path
metadata = json.loads(sys.argv[1])
host = tuple(metadata['namespace'])
current = os.stat('/proc/self/ns/net')
if (current.st_dev, current.st_ino) == host:
    raise SystemExit('Нет изоляции network namespace')
for target in ('/tmp', '/run'):
    subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=16M','tmpfs',target], check=True, timeout=5)
subprocess.run(['/usr/bin/mount','-t','sysfs','sysfs','/sys'], check=True, timeout=5)
runtime = Path('/tmp/yonik-private-runtime')
runtime.mkdir(mode=0o700)
env = os.environ.copy()
env['XDG_RUNTIME_DIR'] = str(runtime)
env['YONIK_NFT_TEST_HOST_NETNS'] = f'{host[0]}:{host[1]}'
if metadata.get('engine'):
    env['YONIK_SYSTEM_TUN_ENGINE'] = metadata['engine']
    env['YONIK_SYSTEM_TUN_BINARY'] = metadata['engine_binary']
if metadata.get('worker_binary'):
    env['YONIK_WORKER_BIN'] = metadata['worker_binary']
listing = subprocess.run([sys.argv[2], '--list', '--format', 'terse', '--exact', sys.argv[5]], env=env, capture_output=True, text=True, timeout=5)
if listing.returncode or listing.stdout.strip() != f'{sys.argv[5]}: test':
    raise SystemExit('Нужный Rust test отсутствует; ноль тестов не является успехом')
raise SystemExit(subprocess.run(sys.argv[2:], env=env, timeout=90).returncode)
"""


def command(
    binary: Path,
    case: str,
    engine: str | None = None,
    engine_binary: Path | None = None,
    worker_binary: Path | None = None,
) -> list[str]:
    namespace = os.stat("/proc/self/ns/net")
    if case == "worker-tun":
        mapping = (
            ["--map-users=0:0:2", "--map-groups=0:0:2"]
            if os.geteuid() == 0
            else ["--map-auto", "--map-root-user"]
        )
    else:
        mapping = ["--map-root-user"]
    return [
        "/usr/bin/unshare",
        "--user",
        *mapping,
        "--net",
        "--mount",
        "--pid",
        "--fork",
        "--mount-proc",
        sys.executable,
        "-c",
        _BOOTSTRAP,
        json.dumps(
            {
                "namespace": (namespace.st_dev, namespace.st_ino),
                "engine": engine,
                "engine_binary": str(engine_binary) if engine_binary else None,
                "worker_binary": str(worker_binary) if worker_binary else None,
            }
        ),
        str(binary),
        "--ignored",
        "--exact",
        CASES[case],
        "--nocapture",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--engine", choices=("xray", "sing-box"))
    parser.add_argument("--engine-binary", type=Path)
    parser.add_argument("--worker-binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Нужен исполняемый Rust test binary")
    if args.case in {"compiled-tun", "unsupported-tun", "worker-tun", "worker-process"}:
        if args.engine is None or args.engine_binary is None:
            raise ValueError("Для compiled-tun нужны --engine и --engine-binary")
        if args.case == "unsupported-tun" and args.engine != "sing-box":
            raise ValueError("Для unsupported-tun нужен sing-box без adapter feature")
        engine_binary = args.engine_binary.resolve(strict=True)
        if not engine_binary.is_file() or not os.access(engine_binary, os.X_OK):
            raise ValueError("Нужен исполняемый закреплённый engine")
    else:
        if args.engine is not None or args.engine_binary is not None:
            raise ValueError("Engine допустим только для compiled-tun")
        engine_binary = None
    if args.case in {"worker-tun", "worker-process"}:
        if args.worker_binary is None:
            raise ValueError("Для worker нужны --worker-binary")
        worker_binary = args.worker_binary.resolve(strict=True)
        if not worker_binary.is_file() or not os.access(worker_binary, os.X_OK):
            raise ValueError("Нужен исполняемый yonik-worker")
    else:
        if args.worker_binary is not None:
            raise ValueError("Worker допустим только для worker-tun/worker-process")
        worker_binary = None
    run_sandbox(
        command(binary, args.case, args.engine, engine_binary, worker_binary),
        timeout=100,
    )
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    install_signal_handlers()
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        LOG.error("Проверка не выполнена: %s", error)
        raise SystemExit(1) from None
