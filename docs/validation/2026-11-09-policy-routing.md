# Общая DNS-политика и нативная маршрутизация

9 ноября 2026 года. [План](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-09-policy-compiler.md).
Продолжение FR-08/11/14/15/20/21, не закрытие полного G-DNS/G-LINUX/G-APP.

## Portable модель

DomainName нормализует UTS46 IDNA, регистр, ASCII/Unicode root-dot и проверяет
DNS labels/длину. Exact/suffix соблюдает границу метки; обычные CDN-имена с
внутренними дефисами допустимы. DomainName Debug скрывает значение.

Conditions объединяет значения domain/CIDR через OR, затем источник и назначение
через AND. Источник проверяется до DNS обычного правила. Порядок: защищённые
приватные сети/зоны → LAN → user → preset → default. Старый evaluate(Flow)
поддерживает только literal IP; DNS/fake/explanation использует evaluate_destination.

Evaluation возвращает Decided с origin/VPN ID, NeedResolution(Policy/VPN resolver)
либо Rejected с DnsPolicyUnresolved/DnsPolicyAmbiguous/UnknownFakeMapping/WrongResolver.
Host передаёт complete A/AAAA/NODATA, TTL/монотонное время и network/engine/resolver
epochs. Модель не делает DNS I/O и не считает available доказательством маршрута ОС.
Host не должен переиспользовать epochs при наличии старых cache/mapping, в том
числе после restart; engine epoch идентифицирует сессию, а не номер версии ядра.

Тесты D-01…D-07 и дополнительные случаи доказывают:

- Старший private CIDR требует real lookup раньше младшего domain→proxy.
- Младший ru-direct CIDR не заставляет делать lookup для уже выигравшего домена.
- Any-match по одному полному набору A/AAAA, порядок адресов не меняет победителя.
- Смесь private/public либо разные VPN, включая перекрытие CIDR, неоднозначна.
- Ошибка/неполный обязательный lookup не проходит к младшему правилу; NODATA
  одного семейства при успешном другом не равно timeout.
- Внутренний домен при отсутствии VPN блокируется до DNS; нужен только его resolver.
- TTL/любой epoch инвалидирует ответы; fake mapping связан с session/engine epoch,
  адресом и временем. Неизвестный fake либо fake-IP в real DNS answer не принимается.
- Literal IP со known name сравнивает CIDR только со своим адресом. IPv4-mapped
  адреса канонизируются; mapped CIDR notation отвергается в пользу IPv4 записи.

## Исполняемые режимы

| Режим | Поддержано | Явный отказ |
| --- | --- | --- |
| names | exact/suffix, default, недоступные private zones, порядок user/preset | CIDR/LAN/private networks с обязательным lookup |
| ip-only | CIDR/LAN/default, недоступные private networks, user/preset | Доменные правила/зоны; все доменные SOCKS назначения блокируются |
| Оба | proxy/direct/block, disabled без эффекта, статические ошибки | Process attribution локального SOCKS, available VPN без NetworkHost binding |

Native ingress принимает канонические ASCII/punycode имена. Raw Unicode/root-dot,
невалидные labels и слишком длинные имена блокируются до default; policy input
нормализуется общей моделью. Смешанный domain/CIDR нативный путь не выдаётся за
реализацию полного resolver контракта. Служебный probe имеет отдельный inbound
и случайный 256-bit SOCKS пароль. Его proxy override не открывает анонимный обход
правил. Host также не отправляет known private endpoint из metadata публичному
серверу; неизвестный remote DNS по-прежнему не объявляется проверенным клиентом.

Release-матрица tools/policy_traffic.py прошла по 93 проверки для Xray 26.10.31
и sing-box 1.14.4. User/network/PID/mount namespace, отдельный /proc, локальные
hosts/адреса и marker endpoints D/P различают реальные DIRECT/PROXY пути.
Проверены TCP/UDP IPv4/IPv6, exact/suffix/IDNA/case/boundaries, порядок/disabled,
защита недоступных private до LAN, mapped IPv4, блокировка имён в ip-only,
raw-invalid wire guard, authenticated/anonymous/wrong-password health, peer-down
контроли и capability errors. Host default BLOCK блокирует данные при успешном
HTTPS204 через отдельный proxy probe; default DIRECT при умершем peer не обходит
его напрямую. Защищённый probe endpoint отклонён до HTTPS, процессы reap.

Policy JSON version 1 ограничен 2 MiB/10 000 rules/100 000 selector values;
неизвестные/duplicate поля и IDs, некорректные IDNA/CIDR/VPN/paths дают статические
ошибки без содержимого. Policy files открываются regular/O_NONBLOCK на Unix.
Конфигурация с правилами и probe credentials проходит прежний immutable config-check
и Session.prepare/apply, оба listener должны принадлежать PID ядра.

Rust 1.85.1: fmt/clippy all-targets -D warnings, 92 теста + 4 compile-fail doctest,
release workspace и Android aarch64 compile-check прошли. Ruff 0.17.4 и четыре
Python unittest прошли. Новых версий внешних пакетов в lockfile нет: используются
уже закреплённые IDNA/serde/getrandom/rustix. Приватная подписка для этой матрицы
не записывалась и не переиспользовалась: здесь только синтетические данные.

## Native DNS gap: доказанный отказ Xray

[DNS context pinned Xray](https://github.com/XTLS/Xray-core/blob/v26.10.31/features/routing/dns/context.go#L27)
возвращает nil при DNS error, а [router](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/router/router.go#L201)
продолжает правила. tools/dns_policy_gap.py воспроизводит это на проверенном binary
SHA-256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1:

1. Новый user/net namespace, только lo; DNS UDP 127.0.0.1:1053 отвечает SERVFAIL.
2. Native IPOnDemand: старшее 198.51.100.0/24→BLOCK, младшее probe.test→DIRECT.
3. DIRECT перенаправлен в локальный marker echo, поэтому новый DNS для соединения
   не маскирует выбор маршрута. Bootstrap DNS имеет отдельный служебный outbound.
4. Получен DNS_FAIL_OPEN_CONFIRMED после одного DNS query с rcode 2; trace содержит
   returning nil и taking detour [direct]. Процесс остановлен/reap, exit 0.

Exit 0 этого теста означает воспроизведение несоответствия, не успешный G-DNS.
Проверен IPv4 SERVFAIL; прочие DNS failure modes требуют отдельной матрицы.
Наш native compiler эту смешанную политику отклоняет. Sing-box имеет resolve/reject
примитивы, но полная эквивалентность D-cases/семейств/пиннинга адресов пока не доказана.

## Границы и следующий gate

Для mixed policy нужен подтверждённый resolver/adapter plan либо пересмотр
архитектуры по networking.md; IPOnDemand не является заменой. Нет full Fake DNS,
системного TUN/DNS, доступного VPN binding, приложения/трея и snapshot updates.
Настоящие network/application/authorization generations ещё принадлежат будущему
NetworkHost, а не полям пользовательского JSON.
