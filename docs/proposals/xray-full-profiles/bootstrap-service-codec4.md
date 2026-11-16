# CODEC4: service bootstrap и полный Hosts path

Контракт следующего canonical codec; production readiness не устанавливает.
SchemaHash = SHA256 ASCII `YONIK-DNS-V2-CODEC-4` + NUL; fallback1/2/3 запрещён.
Kinds/offsets/caps прежние. CODEC3 corpus остаётся basis, CODEC4 получает отдельные
positive/negative goldens. UserDns AUTHORIZE class3 semantics не ослабляются.

## Root и Acquire55

Issuer хранит discriminated UserDns/BootstrapService/HostsPath, не raw-ID alias.
Network BootstrapService: baseLen8, exact Probe8 BE u16 `[2,endpoint,subject,resolver]`,
qtype1/28, resolver!=FFFF, rootId@8 — live services grant с тем же selector.
Flow/revision0 не становится fake USER flow/owner. Path55 — full actual physical
parent frontier, не provider DNS handler path. Issuer восстанавливает все
table2/3/9 transitions/branch mask/carrier; terminal subject/endpoint, original
hostname/port и snapshot role4/source/asset/epoch проверяются точно. Remote proxy
hostname не становится physical leaf; role2 без4 недостаточен.

System DNS transport permit отдельно выводится из captured effective peer/row,
без fake freedom scope. Bundle56 pathCount связывает frontier, не число sockets.
В bootstrap Exchange/Waiter35, Publish40 и Numeric42 carrier — actual parent;
в Physical35/Bind52 carrier/peer — independently checked DNS transport/peer.
Эти назначения удерживаются отдельно. DNS peer не разрешаемый proxy endpoint.

HostsPath: metadata-only Acquire55 с exact Probe8 `[2,endpoint,subject,FFFF]`,
baseLen8, rootId@8=0, qtype/options/payload/resolverRow=0/0/0/FFFF. QueryId/epoch/
original и полный path1..256 сохраняют offsets. Snapshot role4/source custody,
full actual frontier и protected choice contract проверяются; service grants,
transport permits, route tickets и I/O этим variant не создаются.
Initial renewBundleId/expectedRevision0; renewal exact live context/id/revision,
min deadline без resurrection. Chained/merged Hosts передаёт полный path через
tail55: terminal selector недостаточен и не заменяет full context.

Allow56 для Hosts: @8 отдельный HostsPathContextId, @16 rootId0, exact query/epoch/
pathCount/revision, remaining≤1s. Context не DNSBundle/SourceObservation. DATA
decoder не определяет authority; exact pending55 проверяет variant. Bundle и
HostsPath используют единый nonreusing exported context-ID allocator и variant
registry, включая tombstones. Cancel47 target8 в CODEC4 — typed context union;
не допускает смену variant/ownership или коллизии raw ID.

## Observation, receipt и physical permission

Hosts Reserve35 role3 сохраняет bundle/grant0, resolverFFFF/qtype0/queryLen0/
options0/payload0, purpose3/source2/use2/class3/flow0/revision0. Issuer требует
ровно один ACKed HostsPath для exact invocation/queryId/epoch/Probe selector/
original/terminal scope/branch/carrier. Новые bytes в Reserve не добавляются.
QueryId не переиспользуется для unrelated contexts; duplicate/ambiguous/cross-
variant lookup запрещён до effects. Reserved contextId — новый SourceObservationId
после revalidation и pinned-netgo Hosts row/member selection. Observation удерживает
full path и min(source observation≤1s/context/session) deadline. Publish/Waiter/
cache/Numeric lease не продлевают; новый observation требует новой revalidation.
DNS packets, synthetic TTL, network grants и TransportProof для Hosts запрещены.

Probe8 resolverFFFF допустим только в этих CODEC4 Hosts contexts: Acquire55,
Hosts Reserve/Publish binding и Numeric42 use2. Legacy Frame Probe20 и USER-DNS
decoder не ослабляются. Source hashes/observation не transport authority.
Network BootstrapDns Publish/Waiter требуют собственные live service root/
reservation, exact captured question/options/transport proof/revision/source,
strict RRset/absolute TTL. Cache не хранит чужой service grant как authority.

Numeric42 use2/class3 Probe8 принимает только live ACKed typed BootstrapDns/Hosts
waiter/member с тем же full frontier/source/epoch. Target port/carrier — original
physical endpoint. После mandatory numeric policy и durable route installation
GRANT19 прежнего layout имеет class3/flow0/required0/owner0 и хранится только как
BootstrapPhysicalPermission, не USER grant/новый service root/payload permission.
Actual open дополнительно требует live original consumer parent с тем же frontier;
если seam не представляет сочетание двух authority, open Unsupported. Use1 не
принимает bootstrap receipts. Expiry/cancel не создают новые parent grants.

Source/session/root/context cancel отзывает только соответствующие derivatives,
не siblings; refs сохраняются до durable retirement. Все pending/history/FD/
memory/route precredits и Unknown rules прежние. Protected producer pin/schema
обязан явно покрывать physical bootstrap/Hosts capture/actual choice, а не
автоматически наследовать dns_wire/dns_release. Pins/gates закрыты до review.
