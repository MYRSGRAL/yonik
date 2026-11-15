# P4: launch/admission consumer

Это SOURCE/COMPILE/PURE milestone, не завершение P4 и не runtime acceptance.
Follow-up применяется после existing native-broker-codec к pinned Xray26.10.31.
Builder gate остаётся выключенным до transport/grants/DNS-query integration.
Frozen wire/bootstrap, ABI260, upstream commit и dependencies не изменяются.

## Production caller

`main/run.go::startXray` при наличии хотя бы одного private locator выбирает
отдельную ветку, без fallback после ошибки. Она принимает только один bounded
stdin JSON (до65536 bytes), отвергает confdir/другие config paths/test/dump и
вызывает `PrepareProfileLaunch` до `core.LoadConfig`/`core.NewWithContext`.
Parser получает те же bytes, чей SHA256 сравнивается с sealed launch record.
`prepareProfileServer` — общий production caller для pure factory-order tests.
`profileServer.Start` повторяет fence до feature Start; Close сначала отзывает
context, затем закрывает features и только после подтверждённого cleanup — FD.
При ошибке construction/cleanup сохраняется Unknown custody до child stop/reap.
`ProfileRuntime.Revoke` ставит stop fence без освобождения FD;
`RevokeUnknown` сохраняет sticky Unknown, который `Close` не превращает в
KnownClosed. Внутренние terminal states Closed/Unknown различаются явно.

Legacy path остаётся отдельным и не получает нового context/admission/grants.
Check-only с full-profile locators отвергается до Run admission и constructors.
Само наличие locator выбирает parser, но не создаёт полномочий.

## Locator и launch record

Все четыре locator обязательны, decimal FD>=3, без aliases/повторов:

- `YONIK_PROFILE_CONTROL_FD`: private AF_UNIX/SOCK_SEQPACKET channel;
- `YONIK_PROFILE_LAUNCH_FD`: sealed memfd, ровно192 bytes;
- `YONIK_PROFILE_PEER_PIDFD`: retained Host/supervisor pidfd;
- `YONIK_PROFILE_ASSET_ROOT_FD`: retained controlled directory FD.

FD потребляются однократно и возвращаются в CLOEXEC. Входное окружение допускает
только LANG=C и эти locator names. Нет mode/credential из JSON/tag/env value.
Seals требуют WRITE/GROW/SHRINK/SEAL; actual record size/type проверяются отдельно.
Sender credentials проверяются на каждом runtime frame, вместе с live pidfd,
PID/starttime и binding. Rights/unknown ancillary/duplicate credentials/TRUNC/
CTRUNC отвергаются; все доставленные rights закрываются даже при ошибке.

Record layout: magic8@0,version1 u16@8,length192 u16@10,rights u16@12,
reserved0 u16@14,nonce32@16,configDigest32@48,session16@80,invocation16@96,
generation u64@112,epoch u64@120,hostPID u32@128,workerPID u32@132,
hostStart u64@136,workerStart u64@144,manifestHash32@152,reserved0[8]@184.
Все integers big endian. `YNKEXT01` требует rights=1, root sender и exact
current worker PID/start. `YNKLOC01` требует rights=0, worker PID/start=0;
sender UID — normal Host UID. Local record никогда не принимается за System.
Parent counterpart обязан проверить actual child pidfd/PID/start и HELLO после
spawn; pre-spawn нулевые Local worker fields не доказывают child identity.

## Codec и state

Runtime header YNKCAP01/version1 —128 bytes; frame<=65536. Sequence начинается
с1, строго +1; gap/replay/wrap/binding mismatch отзывает канал. Go поддерживает
HELLO1, ADMIT2, ADMIT_ACK3, RENEW21, REVOKE33 и CLOSE_ACK34. Другие сообщения
пока fail closed: это не consumer AUTHORIZE/GRANT и не fake grant endpoint.
Initial deadline1s; session lease<=60s отсчитывается от HELLO send, renewal —
от RENEW send. ACK не продлевает deadline. Один reader/writer и один renewal;
неверный/опоздавший ACK не обновляет состояние. Manifest при renewal неизменен;
новый admissionId монотонный, existing immutable rows не копируются в ledger.
REVOKE/EOF/peer death/expiry отменяют context; CLOSE_ACK сообщает Unknown,
поскольку reader не может утверждать завершение feature cleanup.

ADMIT header128: mappingVersion3 u16@78, tableCount11 u16@120; прочие поля
по revision2.1. Table prefix(type,count,byteLength) занимает8 bytes;
byteLength включает все row prefixes/payloads, исключает table prefix.
Row prefix(rowLength,reserved0) занимает4 bytes; rowLength — только payload.
11 tables и hash domain следуют capsule-mapping.md/resolver-snapshot-contract.md.
SnapshotRef payload76; YNKDNS header120. Transport/proxy/scope/action enums
отдельны от network TCP6/UDP17. Устаревшие mapping/tableCount не принимаются.

Проверяются row bounds до materialization, subject/scope/stream/endpoint/chain
indices, carrier→next input, DAG/path<=256, aliases/owned mode, required flag,
resolver/source refs и asset aggregate. Row caps:256/512/1024/256/64/16/4/1/
512/16/1; static unique leaves<=128. Caps могут только уменьшаться относительно
4096/128/128/64/8388608/30000/4096/256. Metadata/buffer preflight резервирует
512KiB fixed state +3*encoded capsule bytes, retained snapshot bytes и при DAT
2MiB fixed category index +32KiB streaming buffer, внутри общего8MiB budget.
Последующая FlowGrant/buffer integration должна учитывать эти credits совместно,
а не создавать второй независимый8MiB budget.

## Assets

До Allow ACK открываются только `<sha256>.dat` и `dns-<sha256>.bin` через
retained rootFD/openat(NO_FOLLOW), с type/owner/mode/nlink/size/hash и before/
after stamps. Assets<=16 unique, aggregate<=64MiB. Snapshot<=2MiB проходит
полный bounded layout/parser, flags/order/search/options/family/alias checks;
effective peers<=3, duplicates сохраняются. System resolver rows обязаны
соответствовать snapshot peers, включая TCP fallback. Live resolver не вызывается.
DAT streaming parser проверяет pinned protobuf schema, type/category, UTF8,
CIDR prefix, enum/boolean/duplicate/unknown fields. Bounded category index
содержит до65536 SHA256 keys; overflow даёт denial до роста контейнера.

До core parser устанавливается controlled asset-root. Дополнительно existing
`filesystem.NewFileReader` получает closed reader factory, допускающую только
exact owned paths и возвращающую independent SectionReader над retained FD.
Глобальные native asset search paths не дают fallback на чужие contents.
Отдельный cursor каждого consumer не меняет retained FD offset; revoke запрещает
дальнейшие reads. Snapshot object остаётся private, query hooks ещё не подключены.

## Golden и counterpart

`full-profile-fixtures/launch-admission-v3.json` — независимый Python-encoded
synthetic Local record/11-table ADMIT, без actual authority. Та же fixture входит
в upstream patch как common/yonikbroker/profile-launch-vectors.json и проверяется
Go decoder и independent Go fake producer. Rust builder может использовать её
для exact-byte parity; System issuer обязан строить mode2/required1 hash заново.
Hash включает все11 tables, но не admissionId/lease/previousHash, как в contract.

Rust/root integration: передать sealed record и controlled assets до exec;
сверить HELLO nonce/mode/binding/actual child identity; послать authenticated
ADMIT(replyTo=1); считать admission committed только после Allow ACK с exact
manifestHash/admissionId. При renewal сохранять manifest hash и scopes; не
продлевать старые grants через session lease. Optional ACL/owner proofs, durable
direct policy и original-flow receipts принадлежат назначенному issuer.

Дальше нужны actual ingress receipts, per-logical grants, dispatcher/chain/mux
checks, session physical ownership, transport wrappers и snapshot query engine.
Этот milestone не заменяет их session credential и не объявляет полный профиль
доступным. Общая P4 продолжается после интеграции counterpart и transport guards.
