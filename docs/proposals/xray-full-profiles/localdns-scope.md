# Узкое дополнение Go scope: local system DNS

Статус: явно разрешено пользователем. Это дополнение
P4/P5, а не изменение provider DNS policy или frozen ABI260.

## SOURCE evidence

Закреплённый Xray 26.10.31, upstream a4a3dff5b20c2faae567b742c172c7b95e75c083;
retained patched archive SHA256
e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9.

- `app/dns/dns.go:261` уже имеет LookupIPWithContext; передача ctx в QueryIP
  есть в строках 436/539. `app/dns/nameserver.go:183–185` задаёт timeout и
  передаёт ctx в конкретный server.
- `app/dns/nameserver_local.go:20–22` принимает ctx, но вызывает
  `client.LookupIP(domain, option)` без него.
- `features/dns/localdns/client.go:33–39` использует Background для Resolver,
  либо глобальный net.LookupIP. Dial callback в строках 100–113 использует
  net.Dialer; Controllers не получают ctx аргументом.

Hashes двух предлагаемых source members:

- nameserver_local.go:
  5c7128ace2ee1e1acc5fa7da1d6583ded130749601891052c6928ee2d040bd77
- localdns/client.go:
  61a5b767c70295dafae039c4d38eced4d8dbcb548ddcbde748c19b122b86e7ad

Потеря query context подтверждена исходниками. Наличие Controllers само по
себе не доказывает per-query grant, cancellation, resolver snapshot binding
или владение сокетом. Новый обход защиты этим документом не объявляется:
требуется реализовать и проверить недостающий закрытый контекстный путь.

## Запрашиваемая область

Разрешить изменения только:

1. `app/dns/nameserver_local.go` — передать query ctx в context-aware local client.
2. `features/dns/localdns/client.go` — context-aware lookup/dial с переносом
   закрытого FlowGrant/ProbeGrant-derived DNS разрешения, deadline и отмены;
   проверка реального DNS peer по admitted resolver snapshot; сохранение
   socket ownership/release и global revoke. Session credential отдельно
   не выдаёт пользовательский DNS grant.
3. Соответствующие package tests с fake resolver/connections и включение
   этих правок в уже планируемый versioned Xray adapter patch/descriptor.

Закрытые helpers `common/yonikbroker` остаются внутри уже разрешённого P4
scope. Никаких других Go-областей, зависимостей или wire fields этим дополнением
не разрешается. Если потребуется дополнительный caller, нужен конкретный
SOURCE trace до его изменения.

Provider `localhost` DNS не заменяется молча публичным resolver. P5/P8 отвечают
за trusted resolver/NSS snapshot, необходимые routes и custody. Native query
должен сохранять эту привязку и отвергать отсутствующий/чужой/отозванный grant
и устаревший snapshot. Изменение системного resolver не даёт скрытый fallback.

## Проверки и ограничения

Разрешение запрашивается на код, локальную compile-only проверку затронутых
пакетов/тестовых исходников и чистые in-memory tests существующим toolchain
с локальными зависимостями. Проверить передачу ctx, неправильный grant,
отмену и deadline, actual-peer mismatch, смену snapshot, TCP/UDP ownership,
session revoke и отсутствие попытки default resolver при отказе.

Запуск Xray/worker/Host, реальные DNS/network probes и службы не входят.
Изменение ABI260 и новые зависимости не входят. Pure/source результаты
не означают Linux/runtime acceptance.
