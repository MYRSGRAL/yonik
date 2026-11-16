# Завершение DNS: предложение до implementation scope approval

Цель — сохранить DNS и physical hostname semantics семи профилей, включая
provider DNS через proxy. Direct-only lane не считается выполнением этой цели.
Никакой публичный resolver, подмена provider DNS или child-supplied IP не нужны.
Это проект; runtime readiness и новые исходники этим документом не разрешаются.

## Bootstrap, разрывающий cold-start цикл

Pinned `transport/internet/system_dialer.go:52–59,178` использует
`net.ResolveUDPAddr`/`net.Dialer.DialContext` для physical destination.
`dialer.go:242–243,251–281` отдельно обрабатывает explicit socket domain strategy
и dialerProxy; отсутствие стратегии сохраняет системное разрешение физического
first hop. Captured system resolver в этой ветке сохраняет исходное поведение,
а не заменяет provider DNS для пользовательских запросов.

Для каждого фактического hostname physical leaf добавить закрытое requirement
`PhysicalFirstHopBootstrap`: exact subject/table2 endpoint, hostname bytes,
port, TCP/UDP carrier и checked chain frontier. Не включать remote hostname,
который provider protocol отправляет следующему proxy для remote resolution.
Provider JSON и GUI не выбирают произвольный bootstrap target или resolver.

Host/helper захватывают system snapshot даже если у provider DNS app нет
localhost requirement. Источник тот же: retained root-owned NSS/hosts/resolv
и netgo env policy из resolver-snapshot-contract.md, без live fallback.
System resolver rows имеют bootstrap-only purpose; app DNS/rules не меняются.
Existing purpose2 bootstrap_query уже связывает запрос с subject/endpoint;
новый RRset receipt обязан сохранить эту связь до numeric physical open.

Bootstrap использует собственный service grant, Direct DNS transport proof
и при loopback отдельный StubBind. Он может разрешать только exact first-hop
hostname, не пользовательские адреса и не расширение Direct policy. Ответ
проверяется по DNS ID/question/CNAME/RR membership/epoch/TTL; source hosts
имеет отдельный typed snapshot receipt, а не synthetic DNS wire response.
SNI, transport settings и original hostname сохраняются. Все numeric members
проходят captured route/mandatory policy/durable installation до GRANT/open.
Snapshot/stub epoch change отзывает bootstrap receipts и производные grants.
Для synthetic fixtures используется explicit fake captured resolver/RRset;
production не получает fake seed и не требует ручного копирования IP из child.

## Общий provider transport proof

Private exchange runner сохраняет исходный provider route. DirectSocket
использует issuer-retained actual socket; ProxiedLogical — private logical
lineage выбранного handler/stream плюс retained actual first-hop resource set
и полный class3 service-chain bundle. Physical proxy peer не считается DNS peer.
Факт кодирования logical DNS target и чтения plaintext доверяется только exact
protected reviewed producer; issuer независимо сверяет graph/path/grants,
actual physical socket facts/netns/source/route и lifecycle.

Query scopes и class3 children не превращаются в class1 user receipts или probe
authority. Shared pool не выдаёт authority; каждому waiter нужна свежая derivative.
Cache хранит данные/immutable source provenance с absolute TTL/epoch, не чужой grant.
Expired/serveStale/replay/cancel не продлевают TTL и не разрешают publication.

Отдельная versioned DNS transport extension сохраняет ABI260. Typed namespaces:
reservation, physical resource, DNS bundle, logical exchange, StubBind, RRset,
waiter receipt. SCM Bind передаёт actual FD с credentials после reservation ACK;
resource/lineage append подтверждается до handshake/send. Publish ссылается только
на issuer-retained union proof, затем отдельный numeric authorization проверяет
RRset member/port/carrier/full path. Предложенные layouts R29 требуют review до кода.

FD64/pending64/aggregate8MiB и исходные deadlines общие; credits до effect/SCM.
Retire/join отделены от cache lifetime, Unknown сохраняет custody. Shared neighbor
не закрывается отменой waiter. QUIC migration/reconnect/resource replacement
требуют нового admission до use. Compaction history256 — отдельная незавершённая задача.

## Loopback StubBind

Root-owned resolv.conf не является proof сервера. Нужны authenticated system
manager и protected resolver service policy, retained service epoch/cgroup/netns,
полный bounded INET_DIAG socket set с endpoint/UID/cgroup/cookie/state и проверкой
IPv4/IPv6/wildcard/reuseport ambiguity. Missing/partial/stale/replaced proof
закрывает путь; не подменять stub публичным resolver. Local применяет это лишь
при собственной проверке host manager/namespace/mount; не притворяется System.
Доступность kernel facts без новых capabilities и корректность cgroup binding
ещё проверяются SOURCE review; непрерывное владение listener не обещается.

## Минимальное дополнение ownership и проверки

Новые Go точки сверх двух уже разрешённых DNS callers:
`app/dns/{dnscommon,cache_controller,nameserver_cached,yonik_exchange,nameserver_udp,nameserver_tcp}.go`
и adjacent pure tests. Остальные необходимые seams уже в P4 scope: broker,
UDP dispatcher, outbound handler, mux, gRPC/XHTTP/Hysteria, physical dialer.

Rust: существующие profile_channel/issuer/profile_intent и tests; дополнительно
`attribution/broker/kernel.rs` только для общего bounded listener parser/dump,
новый private `helper/resolver_stub.rs` с module declaration; engine native
graph/validate/intent для bootstrap-only requirement и соответствующие tests.
Запись новых upstream/helper/kernel исходников требует отдельного разрешения.

Сначала SOURCE review контракта, затем согласованный bounded wire/codec и goldens,
Direct/Proxy/StubBind producers, per-waiter cache receipts и numeric leaf handoff.
Fake-only acceptance покрывает все семь roots и bootstrap cycle, wrong bindings,
source/stub epoch replacement, duplicate/rights/credit overflow, class separation,
delayed route install, cancellation/Unknown/join и сохранение hostname/SNI.
Без core/Host/GUI/network/services/OS-wrapper исполнения, новых deps/caps или установки.
