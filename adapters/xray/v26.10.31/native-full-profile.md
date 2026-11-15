# P4: незавершённый native full-profile follow-up

Статус: частичный DNS prerequisite; full-profile authority и transport ownership
не реализованы. Builder намеренно не подключает этот patch и не объявляет feature.
Замороженные descriptors, ABI260 и upstream pin не изменяются.

## Реализованная часть

`app/dns/nameserver_local.go: LocalNameServer.QueryIP` передаёт query context в
`localdns.Client.LookupIPWithContext`. Обе resolver-ветки сохраняют этот context;
старый `LookupIP` остаётся совместимым entrypoint. Отменённый query завершается
до resolver. Provider `localhost` не заменяется другим сервером.

Это сохраняет context values, но не проверяет resolver snapshot или allowed peer.
Legacy `LookupIP` по-прежнему не получает flow context. Использовать изменение
как доказательство DNS authorization запрещено.

## Продуктовый blocker: закрытый issuer отсутствует

Проверенный retained archive SHA256:
`e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9`.

- `common/yonikbroker/bootstrap_linux.go: Bootstrap/DecodeBootstrap` декодирует
  session/generation/invocation и Binding, но не admitted manifest.
- `common/yonikbroker/wire.go: Kind/DecodeFrame/EncodeLookup` допускает только
  frozen Hello/Features/Attach/Lookup/Reply/Revoke. Lookup содержит IP tuple;
  Reply доказывает owner, но не policy decision, destination/subject/chain,
  sourceFlowId или provenance. Отдельного service/probe admission нет.
- `common/yonikbroker/closed_tun_linux.go: closedAttach` — private constructor;
  комментарий и codec descriptor явно отмечают отсутствие production issuer.
  `CarryClosedSession` копирует уже имеющийся consumer, не создаёт его.
- `common/yonikbroker/proof.go: guardEntry` отвергает missing consumer.
  Вызов `NewSession` с известным digest не заменяет trusted ingress admission.

## Минимальный следующий контракт для root/P5/P6

Нужен отдельный versioned authenticated carrier, не изменение ABI260: trusted
host issuer передаёт bounded admitted manifest, exact emitted digest, generation,
session identity, expiry/caps, resolver snapshot и allowed peers. Original ingress
и policy issuer должны отдельно выдавать FlowGrant с sourceFlowId, attribution,
provenance/required, исходным и разрешённым destination, subject/chain, expiry и
cancel. Только manifest service issuer выдаёт ProbeGrant. Decoder обязан иметь
конкретный production callsite; произвольные JSON/env/context setters исключены.

Точные wire layout, transport/custody, issuer callsite, authentication и replay
rules этого extension пока отсутствуют в contracts.md. Root должен назначить
их реализацию владельцу host/ingress boundary; Rust helper intent codec сам по
себе такого issuer не создаёт. После согласования можно подключить closed APIs
в yonikbroker и observatory, затем session-owned physical factories и logical
guards в Hysteria/gRPC/XHTTP. DNS hooks должны использовать тот же checked grant
и resolver snapshot. До этого full-profile запуск должен оставаться закрытым.

## Проверки этой частичной поставки

Go `go1.27.1-X:nodwarf5 linux/amd64`, `GOPROXY=off GOSUMDB=off
GOTOOLCHAIN=local`, `-p=1 -mod=readonly`. Скомпилированы localdns test ELF и
Xray main; main не запускался. Выполнен только
`TestYonikCancelledQueryDoesNotResolve`: PASS. RED не зафиксирован; полное
TDD/authority regression acceptance не достигнуто. Builder tests не менялись.
Reverse `git apply --check` на final source прошёл.

Evidence вне TTL:
`/home/myrs/projects/yonik/local/orchestration/evidence/p4-dns-966ee520/`.
До test execution сохранены base/final source archives, compiler ELF и test ELF,
их hashes в before-execution.json; команда и вывод — test-result.json.
Full runtime PASS, strict fresh-base patch-chain verification, transport guards,
grant/race/caps tests и builder apply/pins этой поставкой не заявляются.
