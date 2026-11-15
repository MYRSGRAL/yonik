# Capsule mapping: subjects, scopes и native transitions

Статус: proposed completion scope, implementation не разрешена.
Этот документ заменяет table mapping revision2.1; lifetime/receipt/state правила
revision2.1 с root corrections434b49b сохраняются. Исходный source addendum:
local/orchestration/evidence/p4-dns-966ee520/capsule-protocol-mapping-addendum.md.
Три выявленных compiler gaps исправлены в0aace32 и прошли narrow SOURCE recheck;
это не подтверждает native execution или наличие actual guards.

Финальная proposed capsule имеет mappingVersion=3 и tableCount=11:
таблица11 ResolverSnapshotRef определена в resolver-snapshot-contract.md.
Hash включает все11 tables; промежуточные hashes/layout не принимаются.

## Identity и scope tables

Runtime header, message IDs, leases/receipts из root2.1 сохраняются. ADMIT
tableCount=11 вместо8; таблицы следуют type1..11. Prefix каждой таблицы прежний:
type u16,count u16,byteLength u32; rowLength u16,reserved u16=0 перед row payload.
Big endian; индексы zero-based; 0xffff=None; полный frame≤65536, без chunking.
Caps независимы от total bytes: subjects≤256, scopes≤512, endpoints≤512,
chain transitions≤1024, owned ingresses≤4, provider aliases≤16. Physical unique
leaves≤128 и existing aggregate firewall MAX_EXCEPTIONS не увеличиваются.
Count budget не обещает, что максимальные таблицы поместятся одновременно.
При переполнении 64KiB reject до allocation/admission, без truncation/dedup обхода.

Table1 Subjects теперь только unique identity, ровно compiler outbound order:
name string(u16 bytes+exact validated UTF8≤160), proxyKind u8, reserved u8=0,
streamIndex u16, tcpScopeIndex u16, udpScopeIndex u16.
proxyKind: Vless=1,Shadowsocks=2,Shadowsocks2022=3,Hysteria=4,Freedom=5,
Blackhole=6,Dns=7. SS2022 определяется checked method, не именем tag.
Имена уникальны, не duplicate rows на TCP/UDP. Scopes создаются в subject order,
сначала input TCP6, затем UDP17; строка описывает input текущего handler,
НЕ original flow network и НЕ physical network. У terminal blackhole/DNS
также есть input scopes, но no arbitrary transport grant.

Table9 ProtocolScopes: row payload ровно24 bytes:
subjectIndex u16@0,inputProtocol u8@2,branches u8@3,
normalDial u8@4,normalCarrier u8@5,muxDial u8@6,muxCarrier u8@7,
normalEndpointIndex u16@8,muxEndpointIndex u16@10,
normalActiveStreamIndex u16@12,muxActiveStreamIndex u16@14,
normalChainIndex u16@16,muxChainIndex u16@18,
normalAction u8@20,muxAction u8@21,reserved u16@22.
branches bit0=normal,bit1=outboundMux; прочие bits запрещены.
Action: PhysicalStatic=1,Chain=2,DirectDynamic=3,NoDial=4.
Отсутствующая branch: dial/carrier/action=0, все indices=ffff.
TCP=6,UDP=17,0=нет dial только NoDial; неизвестный protocol reject.
streamIndex=None на branch raw UDP (internet.Dial UDP bypasses configured stream
selector), но subject.streamIndex всё равно связывает полный canonical fingerprint.
EndpointIndex указывает server host/port с normal/mux carrier network.
DirectDynamic endpoint=None, carrier известен, конкретный numeric destination
проверяет AUTHORIZE+mandatory/firewall path root/P5. NoDial: endpoint/stream/
chain=None,dial=carrier=0; DNS proxy пользуется отдельным checked DNS path,
а не автоматически PhysicalStatic. active branch проверяется до actual open.

Table2 Endpoints: Destination из root2.1, затем reserved u32=0; role byte удалён.
Destination family Domain=3,IPv4=4,IPv6=6,protocol TCP6/UDP17. Никакого role3
псевдо-Destination: dynamic classification теперь scopes.Action. Endpoints
dedup по exact validated canonical (family,bytes,port,carrier protocol), first
encounter order по scope normal/mux. Один endpoint может использоваться несколькими
subject scopes, но это не объединяет их authority. Endpoint rows≤512; resolved
IPs остаются проверенными derived observations, не подменяют hostname identity.

Table3 Chains: row payload ровно8 bytes:
sourceScopeIndex u16,nextScopeIndex u16,sourceBranch u8(0normal/1mux),
nextBranchMask u8(bit0normal/bit1mux),reserved u16=0.
Unique key=(sourceScopeIndex,sourceBranch). source scope ChainIndex ссылается
ровно обратно на эту row; nextScope.subject — exact graph chain target.
nextScope.inputProtocol=source branch carrier. Никакого next TCP по умолчанию
и никакого сохранения original UDP без вычисления carrier! nextBranchMask
получается из native mux decision для target=source endpoint (включая port443),
не является свободным caller choice. Leaf определяется повторением transitions,
tag graph должен быть acyclic. Ограничить path≤256; до повторного прохода выделить
bounded visited set. Chains row НЕ разрешает dial source remote напрямую.

Table4 Transports: kind u8 Tcp1/Grpc2/Xhttp3/Hysteria4,security u8
None0/Tls1/Reality2,reserved u16=0,fingerprint[32]. Canonical bytes от
ProfileIntent::write_transport_sensitive(subject): точный P5STRM01 encoding
из указанного P5 ref, body≤64KiB; explicit defaults/Option/ordered Lists
не нормализуются. Fingerprint=SHA256(ASCII YNKCAP-TRANSPORT-v1 || ONE NUL byte ||
exact P5STRM01 bytes). Это не literal backslash+0. Header-custom использует
exact typed Packet.type/packet/rand encoding, не decoded packet и не новый random.
Host сверяет transport_kind со bytes prefix и считает hash сам; actual adapter
factory проверяет тот же typed stream identity, не pointer address.
Probe/destination/chain/subject не входят в fingerprint, но входят в scope/pool key.
Outbound credentials связаны exact final runtime digest и unique subject identity.

Table7 Ingresses остаётся≤4 OWNED actual listeners/TUN/probe rows root2.1.
Table10 ProviderAliases≤16: providerTag string(u16+≤128 bytes),
ownedIngressIndex u16,providerProtocol u8(Socks1/Http2),reserved u8=0.
Unique providerTag, порядок compiler graph.ingresses. Для aliases одного owned
index Host повторяет P3 equality sniffing+membership каждого ordered routing rule;
запрещены unused mappings и collisions с DNS internal tags. Это не 16 listeners.
Alias/index не proof; request issuer берёт provenance из owning ingress receipt.

Tables5/6/8 (resolver/resources/probe) без layout изменений; все их subjectIndex
теперь unique table1 indices. Probe expanded subjects не становятся scope indices.
AUTHORIZE: существующий subjectIndex остаётся table1 identity; после transportIndex
добавить scopeIndex u16,branch u8(0normal/1mux),reserved u8=0. Проверить
scope.subject==subjectIndex,branch active,transportIndex==branch active stream
(None для rawUDP). Grant immutable scope включает эти4 bytes; refresh менять их
не может. Pool key включает unique subject+scope+branch+chain path+stream hash,
session/invocation/digest/gen. Service Probe/physical factory также выбирает
доказанную branch scope, session credential не заменяет logical grant.

Manifest hash сохраняет root domain и scalar fields, но теперь хеширует все
11 tables в wire order (включая новые indices/branches). tableCount=11 фиксирован;
не принимать старый hash как hash minfix. Для согласования schema использовать
capsule mapping version=3 в ADMIT reserved u16@78 (раньше обязано0): точное
значение3; old version0/2 receiver явно отказывает. YNKCAP01 transport version1
и frozen ABI260 не меняются. Это versioned draft extension, не silent compatible
layout change. Общий memory preflight8MiB сохраняется; reserve новые scope rows
и edge/alias decoded capacities до materialization, не расходовать hidden maps.

## Native network function: input → proxy dial → carrier

Определения: P=input текущего outbound Target.Network; D=network аргумента
Handler.Dial; C=network, дошедший до DialSystem. Original sourceFlow protocol
хранится отдельно и никогда не меняется при этих transitions.

| Proxy/branch | D | C без chain | Source anchors |
| --- | --- | --- | --- |
| SS,SS2022 normal | P | P=UDP→UDP; P=TCP→streamCarrier | proxy/shadowsocks/client.go:48–65; shadowsocks_2022/outbound.go:73–91 |
| VLESS normal | TCP | streamCarrier для TCP И UDP logical input | common/protocol/server_spec.go:19–20 задаёт TCP server; proxy/vless/outbound/outbound.go:189–216 dial server, command выбирает target.Network отдельно |
| Hysteria proxy normal | TCP | UDP | proxy/hysteria/client.go:35–37,53–63: TCP ServerSpec + datagram context; transport/hysteria Dial:327–334 форсирует dest UDP; 368–371 выбирает udp/tcp logical API |
| Freedom normal | P | P=UDP→UDP; P=TCP→streamCarrier | proxy/freedom/freedom.go:386 Dial destination; internet/dialer.go:48–72 выбирает transport только для TCP |
| Outbound mux worker | proxy Process input=TCP synthetic mux target; затем правила proxy выше | Для SS worker UDP исходного пользователя НЕ означает physical UDP | common/mux/client.go:138–166 задаёт TCP v1.mux.cool и Background; proxyman/outbound/handler.go:207–239 выбирает mux/xudp до proxy.Process |
| Blackhole/DNS | нет общего правила D | NoDial, отдельный DNS backend admission | Не создавать endpoint из отсутствующего proxy dial |

streamCarrier для D=TCP:
Tcp→TCP (tcp/dialer.go:20–27),Grpc→TCP (grpc/dial.go:102–130 явно TCPDestination),
Hysteria→UDP (hysteria/dialer.go:333–334),Xhttp→version-dependent:
Reality→HTTP2/TCP; no TLS→HTTP1.1/TCP; TLS with exactly ALPN=[h3]→HTTP3/UDP;
иначе HTTP1.1/TCP при exact [http/1.1], иначе HTTP2/TCP.
Anchors splithttp/dialer.go:82–108,118–125,194–205,247–269,293–300.
Нельзя утверждать «весь XHTTP physicalTCP» без проверки ALPN.

Для D=UDP internet/dialer.go:66–71 ВСЕГДА выбирает registered udp dialer,
не grpc/xhttp/hysteria. udp/dialer.go:14–22 вызывает FinalMask.DialUDP или
DialSystem с тем же UDP. Configured security/transport не превращает его в TCP.
Поэтому SS UDP branch.activeStream=None даже если subject fingerprint=Grpc.
SS с configured Hysteria: UDP input также bypasses Hysteria transport и использует
raw SS UDP, а TCP input проходит Hysteria carrier; сохранить обе ветки.

Header-custom не меняет network: TCP finalmask callback memory_settings.go:70–71
и UDP callback:76–93 вызывают DialSystem с данным dest. Старый UDP wrapper panic
остаётся P4 implementation blocker, не причина unwrap/skipguard.

Outbound mux branch разрешать только по actual native decision:
handler.go:120–165 создаёт mux managers только при mux.enabled=true;
concurrency0 становится8,concurrency<0 создаёт disabled manager.
handler.go:207–237: если h.mux!=nil, для UDP443 reject→deny,skip→normal;
далее UDP с h.xudp!=nil выбирает enabled xudp, disabled→normal; иначе enabled
h.mux→mux, иначе normal. На top-level inputUDP target port динамический,
поэтому scope может иметь обе branch bits. На chained hop target=source endpoint,
его port известен Host, nextBranchMask вычисляется точно; reject port443 не edge.
Не путать outbound mux/XUDP с XHTTP xmux manager: XHTTP pooling не превращает
proxy input protocol; оно использует streamCarrier и per-logical authorization.

## Chain: carrier source → input next

Checked true-chain теперь lowering-ится compiler0aace32 в sockopt.dialerProxy.
infra/conf/transport_sockopt.go:51,166–171
переносит dialerProxy в SocketConfig. Handler.Dial (handler.go:268–275)
вызывает internet.Dial с текущим proxy dest и streamSettings. После выбора
factory и network conversion DialSystem (internet/dialer.go:270–278) вызывает
redirect по sockopt.DialerProxy; redirect:111–135 добавляет новый Outbound{
Target:dst,Tag:next} и напрямую вызывает nextHandler.Dispatch без DefaultDispatcher.
Следовательно next input P=C текущего transport, next target=server endpoint
текущего subject. Следующий proxy снова вычисляет собственные D/C, независимо
от original flow network. Guard только в DefaultDispatcher недостаточен:
actual chain redirect и Handler.Dispatch требуют private transition check.
context.WithoutCancel в redirect:123 сохраняет values, но отцепляет cancel;
нужен session physical ownership плюс отдельный logical cancel, не доверие ему.

Синтетические примеры, НЕ actual traffic:
- original UDP → VLESS/Grpc A: D6,C6 → SS B input6: D6,C6 → physical TCP B.
- original TCP → Hysteria A: D6,C17 → SS B input17: D17,C17 → physical UDP B.
- original UDP → SS A normal: D17,C17 → VLESS/Grpc B input17: D6,C6 → physical TCP B.
- original UDP → SS A mux worker input6: D6,C6 → SS B input6 → physical TCP B.
- original UDP → VLESS/Xhttp ALPN[h3] A: D6,C17 → VLESS/Grpc B input17 → C6.
Таким образом ни «TCProw всегда», ни «сохранять UDP по chain» неверны.

## Host derivation и adapter actual checks

Host из P5 typed intent: unique subjects/proxyKind/settings; stream enums и
P5STRM01 hash; original tag edges; explicit owned mappings; отдельно root
manifest/P5 checked resources/resolvers. По таблице3 вычисляет scopes/branches
и transition matrix. Не вывести протокол из EgressPlan.chains одних tag edges.
Проверить scopes(TCP,UDP) indices, subject/endpoint mappings, acyclic graph,
endpoint protocol==C, next input==C, nextTag==checked edge; конечный static leaf
должен совпасть с P5 PhysicalRequirements по host/port/protocol. Chained remote
не добавлять в direct exceptions. Неполный typed accessor → typed rejection,
не JSON scrape и не доверие caller-provided transition. Existing public
transport_kind/write_transport_sensitive недостаточно для всех proxyKind/mux
decisions: codec validator/builder внутри trusted P5 module имеет private fields;
root должен назначить closed projection getter, не произвольный Value constructor.

Adapter: при root logical request выбрать scope input=actual Target.Network,
при actual factory сравнить D/C и stream identity, при redirect проверить exact
nextScope/target/branch, не подменяя immutable original/sourceFlowId. При gRPC/
XHTTP reconnect проверять session manifest physical lease и тот же chain path;
каждый logical open/reuse/send проверяет свой grant, не authority первого flow.
SS/Hysteria UDP каждый payload проверяет actual payload.UDP (и endpoint override),
не cached cone destination. Scope не разрешает arbitrary resolved peer/port:
snapshot/provenance и mandatory dynamic firewall checks остаются обязательными.
Не копировать protocol account/first stream attribution на next logical flow.

