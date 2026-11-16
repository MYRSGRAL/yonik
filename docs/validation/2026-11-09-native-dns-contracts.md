# G-DNS: новые native-контрпримеры

Стенд проверяет Xray 26.10.31 и sing-box 1.14.4 с прежними закреплёнными SHA-256.
Это доказательства ограничений штатной конфигурации, а не успешный G-DNS.
Продуктовый compiler по-прежнему отклоняет смешанный DNS/Fake-IP режим.

## Изоляция и достоверность

Каждый инструмент проверяет inode network namespace и единственный интерфейс lo
до `ip`-операций. User namespace сохраняет capabilities через `--keep-caps`;
PID/mount namespaces и отдельный `/proc` ограничивают cleanup. Физическая сеть,
системный DNS, firewall и чужие процессы не меняются. Только reserved/loopback IP,
синтетические имена и локальные TCP-маркеры; реальная подписка не используется.

`dns_fixture.py` ограничивает packet/records, проверяет ID/question/owner/family,
compression pointers, truncation/rcode и trailing bytes. Пять новых unit-тестов
покрывают IPv4/IPv6, NODATA, TTL, ошибочные ответы/петли/границы и cleanup UDP server.
Ruff 0.17.4 format/check и все двенадцать Python unit-тестов прошли.

Native config-check обязателен. Процесс должен быть жив после запроса, затем
останавливается/reap в context manager. Отказ SOCKS сам по себе не считается
доказательством routing: положительные контроли должны вернуть точный marker,
отрицательные — не достигнуть marker listener.

## Неполный набор A/AAAA — sing-box

`tools/dns_dual_stack_gap.py`: локальный UDP resolver и native route.resolve с
двумя семействами. Перед разрешающим правилом стоят старшие блокирующие
CIDR для обоих семейств. Каждое семейство реально запрошено ровно один раз.

| DNS outcomes | Фактический результат |
| --- | --- |
| A SERVFAIL, AAAA SERVFAIL | Нет connect/marker |
| A valid, AAAA valid | Успешный marker |
| A valid, AAAA SERVFAIL | Успешный IPv4 marker |
| A SERVFAIL, AAAA valid | Успешный IPv6 marker |
| A valid, AAAA входит в старший BLOCK CIDR | Нет marker, несмотря на разрешённый A |

Два partial случая противоречат требованию D-05: ошибочное семейство не исключает старшее блокирующее условие.
Последний контроль показывает, что успешный AAAA под старшим CIDR меняет решение
на BLOCK при том же разрешённом IPv4.
Aggregate resolve error прерывает route, но ошибка одного семейства скрывается
успешным результатом другого. См. [client](https://github.com/SagerNet/sing-box/blob/v1.14.4/dns/client.go#L474-L497)
и [router](https://github.com/SagerNet/sing-box/blob/v1.14.4/dns/router.go#L1000-L1019).

Evidence: `local/validation/native-dns-contracts/dual-stack/higher-cidr/result.json`, пять
native config/log рядом. `gate_supported:false`, `mismatch_reproduced` означает
успешное воспроизведение ограничения, а не прохождение продуктового gate.

## Привязка route lookup к dial — Xray

`tools/dns_pinning_gap.py`: старшее CIDR 198.51.100.20/32→BLOCK, младшее
pin.test→DIRECT. DNS cache/fallback выключены, direct использует ForceIPv4.

| DNS последовательность | Полученный marker |
| --- | --- |
| .10 при route и dial | A на .10 |
| .20 уже при route | Ни A, ни B; один DNS lookup |
| .10 при route, .20 при dial | B на .20; два DNS lookup |

Последний случай показывает, что проверенный набор не закреплён за фактическим
соединением: повторный DNS достигает IP, который блокировался контрольным правилом.
Это не новый bypass в tofu: unsafe-конфиг создаёт только изолированный стенд.
Source: [dispatcher](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/dispatcher/default.go#L416-L456),
[freedom](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/freedom/freedom.go#L242-L325).

Evidence: `local/validation/native-dns-contracts/pinning/run-1/result.json`,
три native config/log, exact markers/hit counters и DNS transcript.

## Native Fake-IP lifecycle — оба ядра

`tools/fakeip_epoch_gap.py` использует намеренно маленький валидный pool
198.18.0.0/30; Xray poolSize 2. Начальный адрес для name-0 достигает M00.
Обратное отображение проверяется через SOCKS; перехват пакетов TUN и системные
маршруты fake-пула этим сценарием не проверяются.
Ограниченная последовательность новых DNS-имён добивается повторной выдачи этого
адреса другому имени; старый адрес затем достигает маркера нового имени.

В первом зафиксированном TTL-стенде:

- Xray: DNS TTL 1 секунда, повторная выдача после четырёх allocations; старый адрес
  достиг M03 примерно через 0.004 с, внутри исходного TTL.
- sing-box: DNS TTL 600 секунд, повторная выдача после двух allocations; старый адрес
  достиг M01 примерно через 0.002 с, внутри исходного TTL.
- В пустой новой сессии старый адрес не достиг marker; после новых allocations
  в том же pool он снова стал обозначать другое имя. Конкретный Xray offset зависит
  от времени, поэтому номера новых имён в повторном запуске могут отличаться.

Это проверка поведения при малом/исчерпанном пуле, не оценка вероятности на default
pool или benchmark нагрузки. Полный D-07 и поведение всех app DNS caches этим не
объявляются проверенными. Неизвестный mapping блокируется; опасно именно новое
значение уже выданного адреса. Source: [Xray allocator](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/dns/fakedns/fake.go#L73-L128),
[sing-box store](https://github.com/SagerNet/sing-box/blob/v1.14.4/dns/transport/fakeip/store.go#L107-L152).

Evidence: `local/validation/native-dns-contracts/fakeip/ttl-proof/result.json`,
DNS TTL/transcript, начальный/повторный/новый-session markers и native config/log.

## Исправление review самого стенда

P2: FakeIP-проба только записывала `within_original_ttl`; истёкший TTL не вызывал
ошибку. Mock с TTL 1/elapsed 2 воспроизвёл ложный успешный возврат. Теперь возраст
измеряется один раз, проверяется до формирования контрпримера; неожиданное
завершение ядра также отклоняет прогон. Отдельные тесты live/expired/dead-engine
проходят. Native-проба обоих ядер повторена успешно со строгой проверкой TTL,
живого процесса и reap: `local/validation/native-dns-contracts/fakeip/review-fixed/result.json`.

## Следствие для реализации

Одного guard `ip:[0/0,::/0]`, SERVFAIL frontend или короткого DNS TTL недостаточно
для доказательства полного контракта. Нужны атомарная full-family lease, её перенос
в dial и владение mapping между TTL/epochs/pool exhaustion. [Рабочий план](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-09-strict-dns-adapter.md)
фиксирует требования, но выбор native hooks/другого адаптера ещё не принят.
Go-код, бинарники и compatibility manifest этим этапом не изменены.

Полный objective, G-DNS/G-LINUX/G-APP, live Wayland и G-POWER остаются открытыми.
Результаты не разрешают включать fake-DNS toggle в GUI как работающую функцию.
