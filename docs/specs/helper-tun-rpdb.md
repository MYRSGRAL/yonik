# Управляемые правила RPDB для TUN

Продолжение [адресов и маршрутов](helper-tun-configuration.md), P12/P13.
Executor — часть helper; он не включает системный режим GUI самостоятельно.

## Фиксированный селектор

`TunRule::new(priority, table, mark, ipv6)` принимает priority 1…32765,
отдельную таблицу 256…u32::MAX−1, mark 1…i32::MAX и одну семью IP.
Остальные selectors закрыты: action lookup, protocol 253, `not fwmark` с полным
32-битным mask, source/destination unspecified /0. Сокеты worker с этой mark
обходят собственный TUN и продолжают существующую RPDB. Правила private VPN/LAN,
приоритеты других managers и смена сети требуют отдельного host reconcile.

Новый `Resource::TunRule` хранит tun_id, ifindex, priority, table, mark и семью.
Документ журнала требует родительский TUN. Правило не имеет собственной
kernel-метки владения: доказательство — confirmed journal и полная TUN alias
в модели доверенных CAP_NET_ADMIN actors, затем exact match всех kernel fields.
Наличие protocol 253 или совпадение priority само по себе недостаточно.

## Создание и повторная сверка

Перед созданием требуются confirmed parent, совпавший ifindex, actual default
route соответствующей семьи и только confirmed собственные маршруты таблицы.
Любая чужая ссылка на таблицу или коллизия priority в той же семье отклоняется.
Сначала durable intent, затем CREATE|EXCL, строгий ACK и exact dump, затем
Confirmed. Неоднозначная ошибка записи не приводит к автоматическому retry.
Existing Intent после reopen не даёт права присвоить совпавший kernel rule.
Confirmed+Absent требует явного cleanup и нового intent.

Matcher сверяет family, source/destination/prefix, TOS, action, flags, priority,
table, fwmark/mask, protocol; запрещает goto, UID/interface/protocol/port selectors,
suppress/l3mdev и неизвестные attributes. Kernel sentinel
FRA_SUPPRESS_PREFIXLEN=u32::MAX означает отсутствие suppression и допускается;
реальный suppress-prefix отвергается. Неизвестное представление — отказ.

Confirmed own rule references допускаются при ensure_route; добавление нового
собственного префикса возможно, но атомарное переключение поколений и временную
защиту обязан обеспечить session host, а не отдельная Netlink-операция.

## Stop и recovery

Удаление: rules → routes → addresses → TUN. Route нельзя удалить, пока journal
содержит ссылающийся TunRule; generic cleanup не вызывает такой callback.
Rule cleanup требует exact actual rule и confirmed parent anchor; потеря
собственного default route не должна мешать удалить всё ещё принадлежащее rule.
Чужие routes/references сохраняются и дают отказ. При отсутствии rule журнал
сверяется как Absent; удаление не получает broad selectors или flush.

Общая потеря worker, kill switch и восстановление обычной сети остаются
обязанностями [интеграции системной сессии](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-system-session-integration.md).
Эти операции пока не исполняются в пользовательском host namespace.

## Приёмка

Canonical case `tun-rule` проверяет actual RPDB, mark bypass, обе семьи,
reopen, конфликты и обратный cleanup. Compiled TUN gate использует тот же
executor и peer за veth в соседнем namespace: loopback local rule не скрывает
ошибку маркировки исходящих сокетов. Полный системный Apply, DNS/Fake-IP,
worker hardening и продуктовый Connect этим gate не заменяются.
[Результаты и ограничения](../validation/2026-11-10-system-tun-rpdb.md).
