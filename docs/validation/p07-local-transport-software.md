# P07: LocalSocks software lowering

Изменение относительно accepted main993943a8343dbc0fd7ef027b8ab4876348cf8ad5.
Основание: законченный source trace `local/orchestration/evidence/p07-native-lowering-contract/contract.md/json`, норматив ports — `2026-11-14-p07-port-protocol-implementation.md`.

Public `compile_policy` и LocalSocks desktop Connect допускают destination transport:
Xray получает network `tcp`/`udp`/`tcp,udp`, port `n,a-b`;
sing-box получает network list, port u16 list, port_range `a:b`.
Границы включительные; gaps не расширяются. Transport AND всей destination-группы;
resource OR остаётся внутри неё. Action/outbound переносятся на внешний sing-box
logical AND, inbound остаётся в destination conjunct. Policy не изменяется,
disabled правила пропускаются, порядок user/preset/default сохранён.
Новых DNS/resolve путей нет. Прежние Names/IP-only/private/platform отказы сохранены.
Дополнительная сумма диапазонов ограничена 4096, lowering одного правила ограничен
типизированными constructors (2 protocols, 16 ranges); существующие checkpoints
до каждого enabled rule и после emission сохранены.

System/TUN, source_selectors DATA validation, SystemPolicy wire и desktop inline
conversion по-прежнему отвергают enabled transport. Capability/ABI/owner/namespace
не изменены. LocalSocks executable selectors по-прежнему отвергаются, включая
их conjunct с ports. UI eligibility и ранний Connect gate различают Local/System.

Добавлены pure source tests: exact JSON keys, все protocol sets, ports 1/65535,
singletons/range/gaps, destination conjunct, logical resource OR, action/inbound,
user/preset/default order, disabled/IDs, mode/process gates, malformed transport,
native wire rejection. Это не runtime enforcement.

Проверки этого leaf: standalone rustfmt 1.85.1 (edition 2024, skip_children),
`git diff --check`. Cargo/test/clippy/ELF не запускались: root capture03 удерживает
build slot. Системный stable rustfmt не работает из-за отсутствующей
librustc_driver; использован уже установленный 1.85.1, без downloads.

Требуется root integration: существующий engine `tests/routing.rs`, тест
`transport_native_adapters_refuse_enabled_preserve_disabled`, ожидает отказ public
LocalSocks compiler. Он вне ownership leaf и оставлен неизменным. Его enabled
assertion следует перевести на System compiler (Local success покрыт новым тестом).
До этой правки полный engine suite заведомо содержит устаревшее ожидание.
Compile, новые tests и pure ELF проверки остаются pending до одного root refresh.
Cores/Host/worker/proc/network/services/VM не запускались. **Full P07/P15 NOT PASS.**

## Correction R2 P1: реальный Local Connect

После ordinary merge a4e57632d3916aa724aa00e223b73885615bc80c (включая
root correction пустого sing-box child и старого engine test) Local Connect
больше не вызывает generic `yonik_engine::compile`.
Цепочка: Command::Connect → `Actor::local_connect_config` →
`persisted_local_draft` → `compile_local_connect` → `compile_policy` →
`session(compiled, ...)` → CheckedConfig::validate → LocalSession.
Pure regression вызывает именно `compile_local_connect`, выбранный этим callsite,
и проверяет UDP/port Block, default, probe override/credentials/отдельный порт;
это source regression, execution остаётся pending.

Actor повторно читает selected profile через select_profile с snapshot revision,
проверяет selected/source IDs, source generation и schedule generation; затем
перечитывает encrypted routing draft, сверяет revision и сериализованное содержимое
с текущим UI draft. Несовпадение/повреждение возвращает ошибку. Compiler использует
fresh server и persisted draft. После await проверяется command generation через
существующий await_current_schedule до создания Cancellation/session task.
Session generation, cancellation, readiness/check/cleanup остаются прежними.

PolicyMode выбирается как в существующем preset compiler: Names при enabled
доменах, иначе IpOnly. Mixed domain/CIDR не получает DNS fallback: прежний compiler
gate возвращает ошибку. Enabled resource reference получает явный Unsupported
(`unsupported_option` в selection helper; существующий ранний draft.policy gate
может вернуть routing_storage раньше). Resource-bound session wiring отсутствует,
поэтому inline-only session не создаётся; refs/AND/OR не отбрасываются.

Probe port выбирается существующей available_port(0), проверяющей TCP и UDP,
с bounded retry и явным отличием от listen. Это существующая проверка доступности,
а не FD reservation: ядро не принимает listener FD, гонка bind остаётся как прежде.
Никакой арифметики port+1. CheckedConfig сохраняет probe_port и ProbeAccess для
LocalSession::check; проверка readiness идёт через private authenticated inbound.

Standalone rustfmt/diff-check выполнены. Cargo/build/test/clippy/ELF и runtime
запрещены до terminal release root capture03; остаются PENDING. Ветка требует
root review/проверки перед merge. Full P07/P15 NOT PASS.
