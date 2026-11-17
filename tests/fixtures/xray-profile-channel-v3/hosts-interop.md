# PURE_STATEFUL_INTEROP: HOSTS

## NETWORK UDP после namespace correction8bdac3c: joint GREEN

Base `1ccad0fcad12b70b9a8bad5eb77948a49e76f512`, exact production patch
`6e1e0f0ee6c0e48f7b77a1e858e594277a8f515d8267c0bdff2f47e7d8a24791`.
Один изменённый native member относительно2619814, всего1307. Go `bindingIDs`
возвращает terminal **position**, Rust exact `physical_hop` guard не менялся.
Production patch/pins не изменены этим harness commit; новая исполняемая
регрессия помещена в test-only overlay, чтобы сохранить exact6e1 source pin.

`TestPurePhysicalPathRowUsesPositionNotScope` реально получает Raw192 из
NETWORK constructor при frontier.scope1/count1 для resolver6/17 и проверяет
pathRow0. Отдельно выполняет тот же Direct getter с count1 и scopes1/7/511;
это DATA getter regression, не выдача Direct USER capability. На старом28a
producer оба Raw cases и Direct case RED; на6e1 GREEN. Unit ACK fixtures только
инициализируют этот отдельный unit test; в joint stdio cases ACK не scripted.

NETWORK Local/System × captured resolver TCP6/UDP17 проходят весь actual путь
57/58→service/context→Physical/Logical→private DNS exchange→strict Publish→
independent parent/service/context/waiter→Numeric17→actual SS Client.Process→
один fake connected UDP send→consuming close/task join→Known cleanup.
Original SS carrier17 отделён от resolver transport. System injected socket
facts используют mark42 из synthetic System plan, Local — mark0; прежний
stdio leaf ошибочно задавал0 обоим modes. Authorizer mark guard не ослаблен.

Матрица21 cases: четыре NETWORK positives, wrong question/member, original USER
parent cancellation, второй packet в том же SS caller, delayed actual Resource
ACK, плюс все12 прежних cases. Wrong question останавливается до Publish/DATA;
foreign member — до original permission/factory. После original-parent cancel
retired также исходная USER seed route, остальные cases оставляют её явно live.
Source/Transcript/Release — отдельные factory5 views с injected reviewed records.
Actual peer/image/USER/Consumed/kernel/route/I/O/manager admission по-прежнему
test leaves; успешный pair не является actual System admission или OS proof.

Cleanup oracle проверяет actual Proof ACK перед Resource Retire, zero-ref/joined
Retired ACK, reservation/exchange/context/binding9 ACK перед service Close32.
Late-ACK case удерживает полученный от Rust Resource46 в Go bridge, проверяет
custody через три normal ticks, затем передаёт **тот же** packet actual accept.
No fake ACK/KnownClosed, no caps/fixture budget increase, no original deadline
renewal. `transport.started == Exchange Reserve.sent` проверяется actual Go
state; conservative issuer Reservation anchor и transcript recheck сохранены.

Evidence `/home/myrs/projects/yonik/local/orchestration/evidence/p5-udp-network-retry`
содержит RED regression, exact native source/compiler/test ELFs до execution,
joint traces, commands и commit binding. Также собран fresh production main ELF
`xray.compile-only` из exact6e1 source, **никогда не исполнявшийся**. Это не builder
candidate/install record и не authority. Protected5 pins/FranceSS readiness и
runtime/public gates не расширены. Ниже сохранена история предшествующего RED.

## UDP NETWORK2619814: actual pair RED на PhysicalBind.pathRow

Base `bafe4b4550879eb8e5d2f55f0797aac92a3f6ba5`; producer
`2619814825cbf97591c3c87974637d0d1a9392bd`, patch SHA256
`28a5644ab84d2a2972db6c04f6da81b6a358d242c053fa122e2df4780c681f24`.
1307 exact native members:1302 byte-exact к предыдущему1305-member HOSTS tree,
три reviewed shared files изменены, два NETWORK files добавлены. Overlay только
добавляет пять прежних test destinations, existing members не заменяются.

Новые strict cases `udp-network-{udp,tcp}-positive` и оба `system-` варианта
исполняют real57/58→Probe20→55/56→Exchange35/36→Physical35/36→raw52.
Далее joint pipeline **не проходит**: raw192.pathRow@162=1, helper retained
physical_hop=0. Go `profileDNSDirect.bindingIDs` возвращает `n.frontier.scope`
(`common/yonikbroker/profile_dns_direct_linux.go:548`), `dnsDirectPhysical`
записывает это в@162. Rust `bootstrap_binding` в `native_dns_roots.rs` сохраняет
`terminal.index`, а `native_dns_transport.rs::match_dns_physical` сравнивает
@162 с этим retained index. Single SS UDP scope=1, checked path position=0;
прежний VLESS TCP scope=0 маскировал несовпадение namespaces.

Все четыре actual NETWORK positives сохраняют RED на этом guard до ACK37,
Logical38, private exchange/Publish, independent waiter/Numeric/send. Нельзя
считать следующие этапы покрытыми, если peer ещё не получил PhysicalAck.
Helper получает actual Raw52 с virtual FD/kernel facts, вызывает actual
factory5 Source/Wire/Release; ответ37 не фабрикуется. Caps не увеличены, packet
не нормализуется, reference guard не убран. Root требуется согласованный scoped
production fix producer/consumer namespace; ownership этого harness его не включает.
Trace и exact source/compiler/ELFs сохранены в
`/home/myrs/projects/yonik/local/orchestration/evidence/p5-udp-network-pair`.
Unknown custody на отказе сохраняет USER/service/resolver routes; это не Known cleanup.

Для продолжения после fix готовы test-only adapters: actual SS consuming caller,
factory5 retained planner со snapshot DNS-first, resolver TCP6 (`usevc`) либо UDP17,
exact framed DNS peer IO, Source/transcript/release5 и actual-negotiation-bound
Physical receiver. `Stdio` выводит retained context/hop/custody диагностику только
после actual issuer result; не вмешивается в decision. Новые cases
`udp-network-udp-{wrong-question,foreign-member,parent-cancel,replay}` и
`udp-network-tcp-late-ack` остаются strict, не xfail; за Physical52 пока не покрыты.
Поздний ACK helper уже реализован: удерживает **полученный** Resource46, проверяет
custody через normal tick и затем передаёт тот же ACK actual Go accept. Анализатор
проверяет Proof ACK до Resource retire и parent9 ACK до service Close32;
hold/release события не пересылаются другому SUT и не создают ACK/authority.

Все12 прежних cases (пять UDP HOSTS + семь TCP) GREEN на этом exact2619814 ELF.
Это подтверждает сохранение их прежнего subset, но не NETWORK UDP readiness.
Source5 pins/FranceSS/public readiness не меняются. Классификация только
PURE_STATEFUL_INTEROP, без runtime/OS/socket/kernel/install acceptance.

## UDP HOSTS: отдельный CODEC5 pair после R89

База Rust `0641f995cc279c9c0f76a9a469bea06ad34218d8`; Go SUT — exact
`04fda581e1c69b432d0196bf2b25b62da66b6315`, profile patch SHA256
`6a0bd7327e27e20b64dc89922110816e0a27ea8c754b9648a2d6e3d9559b6e52`.
1305 native members восстановлены из retained official tree с обратным применением
1e65 patch и чистым применением 04fda patch. Все1299 прежних members и6 новых
сопоставляются по hashes до/после overlay и test execution. Ни один existing
native member не заменяется overlay; production Rust/Go, reviewed pins и gates
не меняются. NETWORK UDP2619814 — следующий отдельный pair, не результат этого cut.

Новые `datagram-interop-{bridge,external}_test.go` включаются только в test binary.
`datagram-interop-ss.go` — **добавленный**, а не заменяющий source member, build tag
`yonikpureinterop`, пакет shadowsocks. Он конструирует Client с fake policy/link
без core.New/NewClient и вызывает неизменённый actual `Client.Process`: AES-GCM
UDP encoder, `ProfileBootstrapDatagramPayloadSize`, private dial, context binding,
две consuming tasks и deferred Close. External test package устраняет import cycle
с private broker fixture. Tag не используется production builder.

Новые overlay destinations относительно exact source:
`common/yonikbroker/datagram-interop-bridge_test.go`,
`common/yonikbroker/datagram-interop-external_test.go`,
`proxy/shadowsocks/datagram-interop-ss.go`; сохраняются оба прежних overlay files.
Compile-only команда с прежними offline/cache env и абсолютным overlay:
`go test -p=1 -mod=readonly -tags=yonikpureinterop -overlay=... -c -o ... ./common/yonikbroker`.
Relay автоматически выбирает named external test
`TestPureStatefulDatagramHostsSSStdioBridge`, Rust endpoint прежний.

Cases: `udp-hosts-positive`, `system-udp-hosts-positive`,
`udp-hosts-foreign-member`, `udp-hosts-parent-cancel`, `udp-hosts-replay`.
Positive выполняет real57/58→55/56→35/36→40/41→independent57/58→55/56→35/36→53/54→42/19,
один fake connected UDP owner, один actual SS encoded send и join двух tasks.
Replay подаёт второй packet в тот же открытый actual SS caller: второй Write
отвергается, factory/send остаются1; второй physical open также отвергается.
Foreign member мутирует только outbound Numeric42 DATA и получает actual Deny19
до factory. Parent-cancel закрывает **исходный USER grant**, а не только derived
waiter binding; consuming gate не допускает factory, actual Close32 USER ждёт
оба cancel9 ACK. Остальные случаи сохраняют исходный USER seed как live neighbor.

Rust использует общий production factory core `BootstrapBinding::create_for`,
вызываемый `prepare_datagram`, с injected PeerCustody/SourceOwner/explicit reviewed5
record. Реальные Local/System OS custody wrappers не вызываются. Planner,
Source checks, launch/config/capsule/snapshot binding и serialized `run_issuer`
не подменены. Descriptor5/ACK выдают противоположные SUT; fallback4 отсутствует.
Source/Wire/Release5 review pins остаются None.

Явно пропущены USER admission/HELLO, protected install/image OS custody и UDP
control/kernel proof exchange. Общий preseed задаёт grant=flow=revision=1,
original USER endpoint203.0.113.9:443/UDP, initiator192.0.2.1:32001→ingress127.0.0.1:1082,
matched Consumed lineage; Go fixture leaf приводится к этим фактам **до**57.
System Known owner2/id77/20ms — fake facts, не OS attribution. В Rust два owner calls
относятся только к USER seed; flow0 Source не вызывает owner backend. USER effective
остаётся requested logical destination, отдельно от SS physical hostname frontier.
Actual USER authorization этого seed не проверяется данным pair.

Fake datagram owner заменяет только connected socket create/read/write/consuming
close; socket/netlink/ioctl/SCM/core/main/services не исполняются. Authority ACK,
permission и KnownClosed не создаются harness. Каждая выдача context/reservation/
producer/waiter/parent требует соответствующий actual terminal ACK. Анализатор
отклоняет cancel9 до собственного context8 ACK и USER Close32 до обоих ACK9.
После cleanup bootstrap routes/contexts/operations retired; единственная USER
seed route остаётся live, кроме parent-cancel, который закрывает её actual frame.
Preseed counts выводятся отдельно, не обнуляются ради cleanup assertion.

Evidence: `/home/myrs/projects/yonik/local/orchestration/evidence/p5-udp-hosts-pair`.
Классификация только PURE_STATEFUL_INTEROP: не runtime/kernel/installed/FranceSS PASS.
Прежние7 TCP cases прогоняются на том же test ELF с явным descriptor4 selection.

Актуальный результат после root `febd859` и Numeric memory correction:
все7 cases GREEN, включая NETWORK Publish→Waiter→Numeric→fake original open→
Known cleanup. Убрана retained копия immutable Binding из Numeric proof;
observed копирует полный path в exact-length credited Vec вместо максимального
буфера. Source/transcript reparsing сохранён, caps/fixture limits не повышены.
Positive: routes=5 суммарно в ledger, original permission=1,
original factory=1, DNS factory/write/
close=1, retained routes/services/contexts=0, receiver consumed-close=1.
Close32 Numeric permission определяется только по actual pending42→Allow19,
отдельно от service roots: для обоих service Close проверяются все cleanup ACK.
Предыдущий раздел RED ниже — история диагностики, исправленная этим результатом.
Evidence: `/home/myrs/projects/yonik/local/orchestration/evidence/p5-numeric-memory`.
Production Go1e65 ELF переиспользован по hash; protected pins не менялись.

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

### Повтор после R79/R81: Publish проходит, WaiterBound остаётся RED

Base `2ff7c6c90d7243d98244dd052892c0e0b08e7c71`; actual Go patch
`1e65fca3adcbcf9cf74bc73a21d47dcae49523073aa91f262c16e3f4fb6d4d05`.
Source получен обратным применением старого profile patch к сохранённому
native-source3c, затем чистым применением нового patch; codec/base сохранены.
Из1299 production members изменились ровно6 файлов, перечисленных в evidence
`fresh-apply.json`; оба overlay добавляют только новые `_test.go` файлы.

Root scratch correction устранила прежний отказ Publish: реальный Published41
Allow получен. Далее actual Bind53 создаёт waiter, но preparation ответа54
повторно вызывает `rrset_reply→bootstrap_rrset_live→observed`. В этой точке
used=39370, limit=58459, суммарный scratch=20016, deficit=927. Предыдущая проверка того
же transcript до waiter storage успешно проходит при used=38274. Source/peer
valid, sticky-invalid=false, deadline/epoch/anchor не изменены. Поэтому actual
issuer возвращает Deny54, actual Go caller завершается с admission denied.
`network-positive` остаётся строгим RED, не xfail. Production budget, fixture
capacity, Source/transcript/parser checks и protected pins не менялись.

Exact anchors: `native_dns_rrset.rs::bind_dns_waiter` резервирует retained
`size_of::<Waiter>()+80` перед reply; `rrset_reply` повторяет source check уже с
этим retained storage; `native_bootstrap_binding.rs::observed` удерживает2048
path scratch и отдельно запрашивает SCRATCH=17968 для strict capture parser
(всего20016 поверх used на входе во view).
Это новый ограниченный production accounting blocker, а не Go wire mismatch.

`network-no-permit` не требует fake KnownClosed: actual Go Direct consumer
консервативно делает sticky Unknown при Deny36 и удерживает свои operations.
Harness сообщает Unknown/custody и проверяет zero DNS/original factories.
Если Go объявляет cleanup complete, но Rust сохраняет route tickets, relay
отклоняет такой результат как `counterpart route custody mismatch`, а не
обнуляет backend ledger. Failure evidence содержит весь bounded packet trace.

Wrong-question теперь GREEN с completed Known cleanup: actual Proof46 Allow,
Resource46 Allow (zero refs/joined), оба reservation48, exchange48, context48
получены **до** service Close32. Fake DNS factory/write/close=1, original
factory=0, Published/Numeric отсутствуют, routes=2 (service/resolver отдельно),
retained routes/context/services=0, receiver consumed-close=1. Анализатор trace
проверяет каждый выданный resource/proof/reservation/exchange/context ID и
соответствующий ACK до Close32, а не только итоговые счётчики; пропуск resource
ACK либо перенос Close32 перед context ACK отклоняется отдельными unit tests.
No-permit и все4 HOSTS regressions также GREEN. Full NETWORK positive/Waiter/
Numeric cleanup пока не подтверждены из-за Deny54. Late refresh active/tomb
не покрыт этим bounded run; production R81 source здесь не изменялся.

Evidence: `/home/myrs/projects/yonik/local/orchestration/evidence/p5-network-joint`.
Все результаты классифицированы PURE_STATEFUL_INTEROP; это не runtime, kernel,
protected install или current-image measurement. Сборка нового test ELF не
является новым protected producer build record; registry/builder остаются3c.

R77: stdin и stdout nonblocking, selector обслуживает чтение и очередь частичных
записей с тем же absolute deadline. Pending write budget≤8MiB; stop frame проходит
через ту же очередь. Нечитающий peer не блокирует timeout/finally. Отдельные pure
Python проверки запускают собственные fake stdio peers и проверяют deadline и join.
