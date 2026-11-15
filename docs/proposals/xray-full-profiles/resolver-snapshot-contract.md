# Resolver snapshot и DAT source: proposed contract

Статус: source implementation разрешена пользователем через completion-scope.md.
Provisioning и actual runtime этим согласованием не разрешены.
Текущий P5 snapshot `hosts: dns`/nameserver-only
не объявляется достаточным для обычной Local/System установки.

## Семантика resolver

Новый resolver сохраняет поведение pinned Xray, собранного существующим builder
с `CGO_ENABLED=0`, а не обещает выполнение произвольных libc/NSS plugins.
Builder pin/toolchain/source и sealed executable hash должны подтверждать этот
режим. Иной build mode требует другого договора и сейчас даёт Unsupported.

Source basis: Go1.27.1 `net/conf.go::lookupOrder` и `net/dnsconfig_unix.go`.
Без cgo используются files/DNS ordering и netgo search/options; неизвестные
NSS sources не запускают plugins. Эффективный order выводится по pinned
алгоритму, не по наличию substring `dns`. Все входы читаются только trusted
capture и проходят bounded parsing; неизвестная/повреждённая grammar даёт отказ,
а не live fallback. Нельзя применить эту политику к cgo-enabled binary молча.

Snapshot охватывает exact `/etc/nsswitch.conf`, `/etc/hosts`, resolver config,
hostname для default search и фиксированную resolver-политику owned child env.
Окружение не может после admission включить другой resolver/browser dialer.
Full-profile child получает env_clear и только LANG=C, необходимые private
FD locators и asset-root из owning payload; resolver/browser/proxy overrides
не наследуются. Legacy launch остаётся прежним. Canonical env-policy bytes —
u16 big endian со значением1, обозначающим именно эту закрытую policy; любой
другой вариант требует новой версии и не принимается под тем же digest.
Стандартный root-owned resolv.conf symlink допустим только через bounded
root-owned chain≤4: сохраняются identity каждого link/parent и target FD.
Проверки NOFOLLOW на каждом шаге, file type/owner/mode, size/content digest и
before/after stamps обязательны; metadata/hash из IPC такими proofs не являются.

Источник не перечитывается native resolver в обход snapshot. Host/helper
удерживает source FDs и identities до cleanup; перед prepare/apply/start и
active sweep проверяет весь набор. Изменение любого source/namespace/route
инвалидирует snapshot и связанные grants. Unknown cleanup сохраняет custody.

## Snapshot asset YNKDNS01

Snapshot передаётся как отдельный typed sealed asset через native resource
payload, не внутри runtime control frame и не через provider path. Owned name:
`dns-<asset-sha256>.bin`. Local stage принадлежит normal Host/child; System —
trusted worker private asset root. В обоих режимах consumer проверяет exact
size/hash/layout до использования и возвращает acceptance вместе с manifest.

Все integers big endian. Максимум asset2MiB; raw source bounds: nss64KiB,
resolv64KiB, hosts1MiB, hostname253 bytes. Source/canonical/decoded/staging
allocations учитываются одновременно, включая retained copies.

Fixed header120 bytes:

| Offset | Поле |
| --- | --- |
| 0 | magic[8]=YNKDNS01 |
| 8 | version u16=1 |
| 10 | headerBytes u16=120 |
| 12 | totalBytes u32 |
| 16 | sourceDigest[32] |
| 48 | nssContentHash[32] |
| 80 | hostsContentHash[32] |
| 112 | reserved[8]=0 |

После header — ровно одна последовательность полей, без padding/trailing bytes:

- resolvContentHash[32]; effectiveOrder u8: Files1/Dns2/FilesDns3/DnsFiles4;
  ndots u8≤15; attempts u8=1..5; reserved u8=0; timeoutMs u32=1..30000;
- flags u16: rotate bit0, single-request bit1, use-vc bit2, trust-ad bit3,
  EDNS-enabled bit4; прочие bits запрещены;
- hostname string, searchCount u16≤6 и ordered search strings;
- peerCount u16=1..16 и ordered peers: family u8=4/6, reserved u8=0,
  port u16=53, address[4/16];
- hostsCount u16≤4096 и ordered rows: canonical alias string, addressCount
  u16=1..16, ordered addresses (family u8=4/6 + address[4/16]).

String: byteLength u16 + canonical ASCII bytes≤253; DNS root/trailing dot и
case-folding следуют pinned netgo rules. Одинаковые aliases coalesce с сохранением
порядка IP; неоднозначная normalization не выбирает произвольную запись.
Парсер отвергает caps overflow до materialization, ничего не обрезает.
Peers — effective ordered list pinned netgo, не все nameserver строки:
`dnsReadConfig` берёт первые три записи, чей IP проходит `netip.ParseAddr`,
в исходном порядке и с сохранением duplicates. При нуле допустимых записей
в successfully captured config используется exact pinned defaultNS:
`127.0.0.1:53`, затем `[::1]:53`. Storage cap16 не расширяет этот effective
list и не позволяет обратиться к четвёртому серверу. Несовместимый с typed
format/mandatory constraints выбранный peer (например zone address) даёт
Unsupported всего snapshot, а не заменяется следующим сервером. При ошибке
open/stat обязательного source нет proof для этого capture: admission отказывает,
не перечитывая live config и не создавая неподтверждённый defaultNS post-admission.
Отсутствие hosts file обозначается отдельной trusted source observation и
пустым списком, не утверждением из UI; отсутствие/нечитабельность прочих
обязательных источников даёт Unsupported до admission.

sourceDigest = SHA256(`YONIK-RESOLVER-SOURCES-v2` + один NUL byte +
u32(nss.len) + nss + u32(resolv.len) + resolv + hostsPresent u8 +
u32(hosts.len) + hosts + u32(hostname.len) + hostname + envPolicy u16=1).
Все lengths big endian; hostsPresent0 означает отсутствие и требует пустых
hosts bytes, 1 — source существует (может быть пустым). hostsContentHash всегда
SHA256(hosts bytes), а sourceFlags.hosts-absent — инверсия hostsPresent.
Metadata identities проверяются отдельно и не заменяются hash.
AssetHash — SHA256 exact YNKDNS01 bytes; это другой digest.

Consumer реализует bounded files/DNS ordering, search/ndots, retries/timeouts,
rotation, TCP fallback, CNAME/RRset и семейства адресов на existing DNS primitives.
`net.DefaultResolver`/live libc/environment fallback запрещён. Cache/singleflight
не объединяют authority разных callers: каждый waiter проверяет собственный
derived DNS grant, snapshot identity, deadline и cancellation.

Loopback stub peer может быть источником DNS, но не blanket exception:
проверяются namespace/bind/route и actual peer до каждого socket/reuse; ответы
не расширяют разрешённый набор peers. Неизвестные NSS/config semantics либо
невозможность сохранить поведение дают конкретный Unsupported, не подмену
provider localhost публичным resolver. Это проверяется fixtures для обычных
files/dns/resolve declarations и stub/search/options, а не чтением user host в tests.

## Связь с capsule

В mappingVersion3 таблица11 ResolverSnapshotRef имеет count0/1. При отсутствии
system resolver requirement — 0; при его наличии — ровно1. Row payload76 bytes:
sourceDigest[32], assetHash[32], assetBytes u32, format u16=1, reserved u16=0,
sourceFlags u32 (hosts-absent bit0, остальные0). Все system rows table5
snapshotHash обязаны равняться единственному table11.sourceDigest; при count0
system rows запрещены. Отдельного resolverSnapshotHash в ADMIT header нет и
добавлять его не требуется. Manifest hash включает таблицу11. Существующий
ADMIT_ACK с Allow по exact manifestHash/admissionId означает, что consumer
проверил и принял все referenced assets, включая sourceDigest и assetHash
таблицы11; дополнительных неописанных полей в ACK не появляется.
Provider resolvers остаются отдельными table5 rows и не заменяются этим asset.

Snapshot asset вместе с DAT входит в existing private asset storage budget:
не увеличивать worker tmpfs64MiB/существующие memory reservations. Максимум16
уникальных staged files включает snapshot; категории одного DAT не создают
дополнительных копий. Если общий набор не помещается — bounded отказ до staging.

## Trusted DAT catalog

Предлагаемый fixed locator: `/usr/share/yonik/xray-geodata/v1/catalog.json`.
Все parents/catalog/DAT root-owned, без group/world write; provider/IPC не
задаёт path. FD/stat/path-identity/hash revalidation обязательны. Catalog≤64KiB,
version1, unknown/duplicate keys и повторные entries отвергаются.

Schema: version и resources≤16; каждый resource содержит kind geoip/geosite,
sha256[32], bytes u64, records u64 и basename `<lowercase-sha256>.dat`.
Один fixed versioned directory, никаких URL/traversal/absolute aliases.
Catalog выбирает только candidate content; existing bounded DAT parser отдельно
проверяет actual bytes/type/category/records против compiler requirements.
Catalog digest, DAT digests/descriptors и snapshot refs входят в admitted seal.

Missing/stale catalog или category — явная недоступность профиля, не пустой
список rules и не download при Connect. Source implementation/tests используют
synthetic fixtures. Доставка реальных data files/root-owned catalog относится
к отдельному install/provisioning шагу P8 с exact hashes; сейчас data не
скачиваются и системные каталоги не изменяются. Refresh catalog не изменяет
уже pinned active result без новой проверки/admission.

## Проверки

Pure fixtures сравнивают эффективный order/search/options с pinned Go vectors;
проверяют четыре nameserver строки, duplicate order, пустой/invalid nameserver
list с defaultNS и Unsupported для неподдержанного selected peer;
проверяют оба family, files hit/DNS fallback, CNAME/full RRset, expiry/cancel,
wrong peer/namespace/snapshot и cache waiter isolation. FD-backed/mocked identity
tests проверяют symlink replacement, mutation и Unknown retaining custody.
Parser tests пересчитывают metadata/hash malformed DAT, чтобы достигать parser,
а не отказывать только на старом digest. Никаких real DNS/host services в tests.
