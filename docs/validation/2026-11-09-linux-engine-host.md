# Linux host локального SOCKS

9 ноября 2026, Linux x86_64. [План](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-09-linux-engine-host.md).
Продолжение EngineHost/FR-03/04/10, не закрытие всех Linux/network gates.

## Реализованный контракт

tofu-linux выполняет I/O, portable crates остаются независимыми от ОС. Tokio
runtime принадлежит CLI. Новые прямые зависимости в lockfile: Tokio 1.54.1,
reqwest 0.12.28 (без default TLS, SOCKS + rustls native roots), rustls 0.23.46,
rustix 1.1.6 и sha2 0.10.9. Ограничение MSRV остаётся Rust 1.85.

- ELF открывается O_NONBLOCK, fstat требует regular executable и размер ≤128 MiB.
  Фактическое чтение тоже ограничено; SHA-256 сверяется с ожидаемым значением.
- Immutable executable memfd получает WRITE/GROW/SHRINK/EXEC/SEAL seals до
  первого запуска. Version/config-check/start используют тот же inode, а не
  исходный pathname. Подмена исходного файла после копирования не влияет на запуск.
- CompiledConfig теперь несёт собственные Engine/port metadata; CheckedConfig
  не принимает отделённый от JSON порт и отклоняет другое ядро. Внешний caller
  не может сконструировать CheckedConfig без version/config-check.
- JSON хранится в памяти; engine stdin — anonymous pipe. SHA-256 тех же байтов
  привязывает Session.prepare/apply. В этом локальном режиме поколения не
  выдаются за настоящий snapshot NetworkHost/прав приложений.
- Процесс получает отдельную process group, пустое окружение с LANG и явно
  унаследованными SSL_CERT_FILE/SSL_CERT_DIR. Core stdio не экспортируется.
- Version/config-check/stdin/readiness ограничены 5 секундами. Отмена идёт
  через watch token, процесс получает TERM, wait до 3 секунд, затем KILL+wait.
  Drop — аварийный kill_on_drop, подтверждение cleanup только после явного await.
- TCP LISTEN 127.0.0.1:port должен иметь inode из /proc/PID/fd. Таблица
  /proc/PID/net/tcp сама по себе не доказывает владение. Проверка повторяется
  до/после HTTPS, выход ядра отслеживается одновременно с запросом.
- Reqwest использует явный SOCKS5h, без env proxy/direct fallback, redirects,
  cookies и connection reuse между проверками. Только HTTPS без userinfo/fragment.
  TLS errors определяются по типу rustls, не по тексту с потенциальным URL.
- HTTPS 2xx → Connected; timeout/TLS/HTTP отказ → Limited, ядро остаётся живым.
  Выход ядра → Error с cleanup. События используют текущий обновляемый Token.

CLI tofu-local читает тело импорта из stdin. Частичные ошибки запрещены без
--accept-partial и явного --server N; выбранный профиль всё равно проходит
capability checks. CLI сообщает parsed/rejected/index без credentials. --once
завершает процесс после проверки. Обычный режим ждёт Ctrl+C/SIGTERM/выхода ядра.

## Проверенные бинарники

Release-архивы проверены до извлечения, только нужный executable:

| Ядро | SHA-256 архива | SHA-256 executable |
| --- | --- | --- |
| Xray 26.10.31 linux-64 | e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 | cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 |
| sing-box 1.14.4 linux-amd64 | 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 | 1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a |

## Исполняемый стенд

tools/engine_host.py создаёт user/network/PID/mount namespace с собственным
/proc и PID 1. Kernel teardown PID namespace убирает даже отдельные process
groups при аварии стенда. Parent владеет TemporaryDirectory, run_sandbox —
внешней process group. Системная сеть, DNS и чужие процессы не меняются.

На каждом настоящем ядре:

1. SOCKS → отдельный VLESS peer → HTTPS с тестовым CA: 204 даёт Connected.
2. Явный выбор из частичного импорта тоже достигает Connected, сообщает ошибку.
3. HTTP 503 и 302 дают Limited, status сохранён, redirect не выполняется.
4. Неизвестный CA и неверное имя сертификата дают Limited с kind=tls.
5. После остановки VLESS peer HTTPS server остаётся доступен локально, но probe
   не проходит: direct fallback нет. В окружении намеренно заданы чужие
   HTTP_PROXY/HTTPS_PROXY/ALL_PROXY и NO_PROXY=*.
6. SIGTERM во время Checking и после Connected, терминальный SIGINT, внезапный
   SIGKILL ядра в Checking/Connected/Limited: ошибочного Connected после exit
   нет, процесс reap. Занятый чужим listener порт не признаётся собственным.

Синтетический Rust ELF проверяет SIGTERM в version/config-check и version timeout.
Он не является proxy engine и не включается в продуктовый workspace.
Unit/integration tests проверяют seals, подмену исходного файла, FIFO, размер,
хеш/версию, блокированный stdin, другой engine metadata, ownership, URL/privacy,
явный partial selection. Отдельный SOCKS fixture подтверждает передачу hostname
ATYP=3 без локального DNS разрешения probe hostname.

## Сборка и приватная подписка

Rust 1.85.1: fmt, clippy --workspace --all-targets -- -D warnings, 69 тестов
и 4 compile-fail doctest, release build и aarch64-linux-android compile-check
прошли. Ruff 0.17.4 format/check и четыре Python unittest прошли. Standalone
Rust fixture дополнительно проверяется rustfmt, в том числе в CI workflow.

Реальная подписка загружена с HTTP 200 только в память, целиком передана
tofu-local через stdin; выбранные записи разрешены явными --accept-partial
--server N. URL, credentials и configs не сохранены и не переданы в argv.
Сначала выявлен конфликт тестового порта с чужим SSH listener: host корректно
остановил собственное ядро без Checking/Connected и не затронул SSH.

На свободных портах Xray для записей 0/1 и sing-box для записи 0 прошли
Preparing → Checking → Limited → Disconnected, probe=timeout за 10 секунд,
exit 2. Каждый процесс ядра проверен как reap после завершения. Sing-box
отклонил запись 1 до запуска из-за XHTTP (exit 1). Одна неподдерживаемая запись
импорта остаётся явно отмеченной. Работоспособность этих удалённых профилей
не подтверждена; успешным подключением timeout не объявляется.

## Границы

Это локальный SOCKS режим: нет TUN, системного proxy/DNS, policy compiler,
хранилища, сетевых обновлений, GUI/трея, статистики и recovery. TCP latency
проверка FR-09 ещё не реализована. SOCKS transport failure не различает причину
удалённого DNS/туннеля: полный диагностический контракт FR-10 ещё не закрыт.
Обычная остановка/SIGINT/SIGTERM проверены; SIGKILL самого host не выполняет
Drop и может оставить core. Persistent supervisor/crash recovery — следующий этап.
Чтение обычного бинарника рассчитано на локальную файловую систему, не на
зависший FUSE/NFS. Поставщик ожидаемого hash должен быть доверенным: совпадение
пользовательского hash само по себе не доказывает происхождение бинарника.
