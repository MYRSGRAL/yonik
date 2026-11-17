# Компиляторы конфигураций одного сервера

9 ноября 2026 года, Linux x86_64, tofu-engine. Продолжение FR-03/04/06/08/10,
не закрытие полных сетевых gates. [План](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-09-engine-compiler.md).

## Контракт

Вход: ParsedServer из tofu-import, Engine и NonZeroU16 порта. Выход:
CompiledConfig с закрытым JSON и скрывающим Debug; только write_sensitive
выдаёт содержимое host. Нет запуска команд, чтения файлов или сетевого I/O.
Один SOCKS inbound на 127.0.0.1, один proxy outbound, без direct fallback.
Повторное направление на собственный IPv4 listener отклоняется, включая
IPv4-mapped IPv6 и localhost с конечной точкой. DNS alias/rebinding требует
повторной проверки разрешённого адреса будущим host: компилятор не выполняет DNS.

Компиляция не равна config-check и не равна Connected. tofu-compile выводит
только метаданные по умолчанию; чувствительный экспорт требует отдельного
--emit-secret-config. CLI не принимает native JSON и частично ошибочный импорт.
Библиотека позволяет host отдельно согласовать выбор из ImportReport.

| Возможность | Xray 26.10.31 | sing-box 1.14.4 |
| --- | --- | --- |
| VLESS, VMess AEAD, Trojan, SS, HTTP CONNECT, SOCKS5 | Да | Да |
| VLESS/VMess/Trojan TCP, WS, gRPC | Да | Да |
| XHTTP для этих протоколов | Да | Нет, явная ошибка |
| TLS, SNI, ALPN, известные uTLS fingerprints | Да | Да |
| VLESS TCP REALITY, Vision | Да | Да |
| Небезопасный TLS, плагины, unknown options, legacy alterId | Ошибка | Ошибка |
| SOCKS поверх TLS, H2/QUIC, native JSON | Пока ошибка | Пока ошибка |

SS: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, AEAD-2022 AES с
проверкой длины Base64 ключа. 2022 chacha — только sing-box. Multi-user
identity chains пока отклоняются. TCP header obfuscation, gRPC authority,
packetEncoding, spiderX и расширенный XHTTP extra пока не реализованы.
TLS всегда проверяет цепочку и имя. Xray получает useSystemCA=true явно:
у закреплённой версии иначе по умолчанию используется встроенный CA bundle.
Plaintext VLESS Xray допускается только к private/loopback/link-local IP;
имена без TLS консервативно отклоняются без выполнения DNS в компиляторе.

## Первичные схемы

- [Xray transport/security](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_security.go):
  REALITY password (publicKey — legacy alias), shortId, TLS useSystemCA.
- [Xray transports](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_method.go):
  wsSettings.host, grpcSettings.serviceName, xhttpSettings.
- [Xray ограничения outbound](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/xray.go).
- [sing-box transports](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/v2ray_transport.go)
  и [TLS](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/tls.go).

## Исполняемые проверки

Закреплённые бинарники скачаны с release-страниц, SHA-256 проверен до исполнения:

- Xray: e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214.
- sing-box: 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968.

tools/engine_compile.py принимает только синтетические fixtures. Новый
user/network namespace проверяется по inode и единственному интерфейсу lo;
host network/DNS не меняются. Parent владеет временной директорией и убирает
всю process group через общий run_sandbox даже при прерывании.

- 10 Xray + 9 sing-box конфигураций прошли config-check: шесть протоколов,
  WS/TLS, gRPC/TLS, TCP REALITY/Vision, XHTTP/TLS у Xray.
- SOCKS → отдельный VLESS server → echo: по 4 успешных TCP/UDP IPv4/IPv6
  потока на ядро; после остановки proxy server ещё по 4 запроса отклонены,
  хотя echo продолжает работать.
- Для каждого ядра VLESS/TLS с тестовым доверенным CA передаёт нагрузку.
  Неверный SNI и недоверенный CA дают отказ. Проверка сертификата не отключалась.

## Приватная подписка

Тело получено HTTPS 200, только в памяти; URL, credentials, адреса и исходные
конфиги не сохранялись. Два VLESS профиля проверялись отдельно как явно
выбранные записи: первый компилируется для обоих ядер, второй использует XHTTP
и компилируется только для Xray. Все три поддерживаемых конфига прошли настоящий
config-check. Третья запись имеет неподдерживаемый протокол.

HTTPS через все три поддерживаемых сочетания завершился timeout (curl 28,
HTTP 000) за 10 секунд. Прямой запрос к тому же generate_204 вернул 204.
Это не доказательство работоспособности профилей или причины их отказа;
Connected и FR-10 не объявлены пройденными. При передаче stdin из Node использован
настоящий anonymous pipe: открытие /dev/stdin для Node socket даёт ENXIO у sing-box.
Отдельный TCP connect к обоим endpoint успешен; это не подтверждает handshake
прокси-протокола или работу HTTPS через него.

## Локальные сборочные проверки

Rust 1.85.1: fmt, clippy --workspace --all-targets -- -D warnings, 56 тестов
и 4 compile-fail doctest, release build всего workspace и Android
aarch64-linux-android compile-check прошли. Ruff 0.17.4 format/check и четыре
Python unittest прошли. Новых внешних зависимостей в lockfile нет: tofu-engine
переиспользует уже закреплённые serde_json, url, base64 и tofu-import.

Независимый review fe1112e..60bcb09 нашёл один P2: IPv4-mapped IPv6 обходил
ListenerConflict. Добавлена нормализация адреса и регрессионный тест для обоих
ядер, localhost./LOCALHOST и разрешённого другого порта. Перед исправлением
тест воспроизводил ошибку.

## Границы

Сетевой handshake проверен для VLESS TCP и TLS. Для остальных протоколов,
REALITY/WS/gRPC/XHTTP пока есть config-check, но нет полной локальной матрицы
handshake/interoperability. Policy, TUN, DNS/Fake-IP, private VPN, host lifecycle,
immutable artifact/digest, хранение, UI/трей, обновления и замеры ресурсов остаются
в общем плане. Выбор GUI toolkit открыт.
