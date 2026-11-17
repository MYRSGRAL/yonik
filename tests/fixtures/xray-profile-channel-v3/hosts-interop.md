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

## System HOSTS без System runtime

`--case system-positive` использует System capsule/`YNKEXT01` с теми же
snapshot/config/path на обеих сторонах. В init явно передаются USER grant/flow
watermark=1, policy revision=1, owner kind=2/id=77 и исходный Known=20ms.
Go проверяет совпадение всего preseed, использует fake proof-channel liveness и
authenticated setup credentials UID0; actual peer/kernel/OS producers пропущены.
Rust flow0 Source/backend по-прежнему не вызывает USER owner lookup.

`--case system-parent-expired` сначала получает реальные ACK вплоть до Numeric
permission. Пока fake clock неподвижен, проверяет live parent, Source capability
и permission. Caller приостановлен до physical factory; fake clock сдвигается
ровно к исходному Known expiry (20ms), без wallclock sleep/renewal. Actual
`ProfileDialBootstrap` обязан отказать до factory; parent deadline не продлевается.
Derived leases также ограничены исходным Known, поэтому тест не разделяет
отдельные причины отказа conjunction. Permission/DATA pointers не являются
authority после expiry. Одна ранее разрешённая route уже установлена и затем
retired через Close/cancel ACK; ожидаются routes=1, factory=0, owner lookups=0.
Это consumer-clock expiry test, не проверка kernel freshness и не System runtime.
Fake Go clock использует фиксированный UTC epoch2100, чтобы real context timers
не истекали от CPU contention. Known duration остаётся20ms, все actual control
fences используют injected clock; expiry-сценарий сдвигает именно его.

Queued cancellation/late ACK не добавлены в этот bounded System cut. Cleanup
Unknown не преобразуется в KnownClosed: тест принимает только фактически
полученные ответы issuer и проверяет terminal custody, как в Local прогоне.

## Local NETWORK с virtual kernel facts

`network-positive`, `network-wrong-question`, `network-no-permit` используют
тот же stdio bridge, но snapshot order2 (DNS first), captured UDP peer
`192.0.2.53:53`, исходный raw TCP hostname frontier `physical.invalid:8443`.
Actual service20/context55, Exchange/Physical Reserve35, Physical52, Logical38,
private DNS exchange, strict Publish40 и отдельный waiter/Numeric выполняются
production actors. Все ответы — от противоположного SUT.

Два новых leaf adapters только test-only: Go consuming socket callbacks
create/duplicate/read/write/close и Rust `Incoming::fake` с независимыми facts
local=`192.0.2.10:32001`, remote=`192.0.2.53:53`, UDP, uid997/mark0,
netns=(4,5), cookie101/inode102. Raw192 передаётся как JSON `physical` event,
не runtime frame/SCM. Это не actual FD/kernel/namespace custody proof.
Go private `profileDNSNetworkExchange`, sealed socket owner, request/response
capture и consuming-close/join actor не заменяются overlay-функциями.
`network-interop-leaves_test.go` — второй новый virtual test file, production
replacements в Go overlay отсутствуют. Shared factory использует три отдельно
injected reviewed scopes и один fake clock origin с issuer; TTL anchor остаётся
исходным Exchange Reservation.started, не временем Publish.

Fake DNS peer строит A/IN response на настоящий request (ID/options/question),
TTL30/member `.80`. Wrong-question меняет только DNS response question: Go strict
parser должен остановить путь до Publish/DATA/Numeric/original factory.
No-permit отзывает injected resolver permit до Physical Reserve dispatch:
Reserved36 должен быть Deny до fake socket factory/Connect. Ранее оплаченные
service/context routes всё равно требуют настоящего cleanup.
Public NETWORK Read/Write и generic DATA/IP APIs дополнительно проверяются как
закрытые. Positive должен получить одну original physical permission/open;
resolver/service tickets считаются отдельно и retired через actual actor barriers.

### Текущий blocker полного NETWORK positive

На frozen production source actual service/context/Reserve/Physical/Logical
roundtrip проходит, peer bytes проходят оба strict parsers. Publish остаётся
RED: `native_dns_rrset.rs::publish_dns` удерживает SCRATCH и producer storage,
затем `native_bootstrap_binding.rs::observed` делает второй reserve
`SCRATCH+2048`. Для этого minimal fixture при входе во view used=52118,
dynamic limit=58459, requested=20016: deficit=13675. Peer/source valid,
sticky-invalid=false, один clock origin и исходный Reservation.started сохранены.
Ни лимит8MiB, ни production accounting/authorization здесь не меняются.
`network-positive` намеренно не переименован в PASS или xfail: root должен
устранить одновременный double-scratch accounting под тем же общим budget,
сохранив independent transcript checks; затем этот же harness продолжит waiter.

`network-no-permit` не требует fake KnownClosed: actual Go Direct consumer
консервативно делает sticky Unknown при Deny36 и удерживает свои operations.
Harness сообщает Unknown/custody и проверяет zero DNS/original factories.
Если Go объявляет cleanup complete, но Rust сохраняет route tickets, relay
отклоняет такой результат как `counterpart route custody mismatch`, а не
обнуляет backend ledger. Failure evidence содержит весь bounded packet trace.

Wrong-question также оставлен строгим regression target: после actual Proof46
Go legacy tick может послать service Close32 до Resource retirement. Frozen
Rust `cancel_grant→cancel_dns_root→transport.cancel_bundle` тогда отзывает весь
issuer с Unknown и retained route/resource custody. Harness не выдаёт fake ACK
и не требует receiver-close counter=1 при Unknown. Полный known cleanup и
NETWORK positive не заявляются до root correction/review frozen producer/issuer.

R77: stdin и stdout nonblocking, selector обслуживает чтение и очередь частичных
записей с тем же absolute deadline. Pending write budget≤8MiB; stop frame проходит
через ту же очередь. Нечитающий peer не блокирует timeout/finally. Отдельные pure
Python проверки запускают собственные fake stdio peers и проверяют deadline и join.
