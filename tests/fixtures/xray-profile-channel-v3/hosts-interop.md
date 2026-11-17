# PURE_STATEFUL_INTEROP: HOSTS

`hosts-interop-bridge_test.go` — test-only Go overlay, компилируемый в пакет
`common/yonikbroker` из exact root-retained native source archive. Production
patch/source не изменяются. Rust endpoint — named test
`pure_stateful_hosts_stdio_bridge`, выполняющий настоящий `run_issuer`.

Запуск после offline compile-only и сохранения source/compiler/test ELF:

Rust compile command внутри собственного locked transient target:
`cargo +1.85.1 test -p yonik-linux --lib --no-run --locked --offline -j1`.
Go compile command внутри exact extracted native source, с
`GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0` и собственными
`GOCACHE/GOTMPDIR`:
`go test -p=1 -mod=readonly -overlay=/absolute/overlay.json -c -o /absolute/go.test ./common/yonikbroker`.
Overlay JSON содержит только `Replace` одного нового absolute
`common/yonikbroker/interop_overlay_test.go` на absolute repo fixture
`hosts-interop-bridge_test.go`. Ни одного production replacement.

```
python3 -B tools/hosts_stateful_interop.py --rust /absolute/rust.test \
  --go /absolute/go.test --output /absolute/evidence/result.json
```

Первый Rust JSON передаёт один canonical capsule/Local launch/snapshot fixture;
capsule затем передаёт настоящий ADMIT frame. Go `admitProfile` проверяет config,
capsule и snapshot и выпускает ADMIT_ACK. `setupDNSV2` и Rust setup обмениваются
настоящими descriptor4/ACK. Relay не создаёт и не подменяет ACK.

Go actual `ProfilePrepareChain` создаёт Source/context55/56, metadata Reserve,
HOSTS Publish, отдельные waiter context/reservation/receipt и Numeric42.
Rust serialized dispatch использует настоящую `BootstrapBinding`/shared planner,
с test-only injected peer/source owner/reviewed Source record и durable backend.
`ProfileDialBootstrap` требует обе authority gates и вызывает только fake
`net.Conn` factory. После Close и explicit owner cancel обе стороны выполняют
настоящий retirement protocol. Socket/syscall factory не используется.

Пропущены HELLO/OS peer authentication, protected install/image validation и
USER admission: исходный USER parent id=1 явно preseeded; Rust allocator имеет
тот же watermark. Это условие harness, а не доказательство USER authority.
Fixture — один raw TCP leaf, hostname `physical.invalid:8443`, один hosts member
`203.0.113.80`; no TLS/mux/UDP/chain/network DNS. Public gates не меняются.

Relay ограничен 64KiB packet, 140000-byte line, 512 events/8MiB transcript и
absolute timeout≤60s. При ошибке завершает только собственные test processes.
Результат классифицируется `PURE_STATEFUL_INTEROP`, не runtime/kernel/installed
acceptance и не доказательство actual physical open.

`--case foreign-member` меняет только numeric destination последнего42 wire
packet после Go dispatch: `.80→.81`. Actual Rust issuer должен вернуть Deny,
actual Go consumer — завершить caller без factory и выполнить cancel cleanup.
До Numeric ACK положительный прогон также вызывает actual physical gate и
проверяет отсутствие factory effects.
