# Закреплённый worker системной сессии

Продолжение P09/P12/P13 и [плана интеграции](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-system-session-integration.md).
Это транспорт, launcher и supervisor; действующий public-protection IPC пока
не принимает системные профили, capability system_tun остаётся false.

## Передача проверенного результата

TrustedRegistry создаёт неизменяемый BinarySnapshot. WorkerPayload связывает
его с bounded CompiledConfig, digest и sealed config memfd. Клиентский IPC не
получает способ передать executable path, argv, среду или raw engine JSON.
Header приватного канала содержит только version/mode/engine, размеры и hashes;
два SCM_RIGHTS FD передаются с CLOEXEC. Получатель требует UID 0 у peer,
правильный mode, точное число FD, seals, длины, digest и отсутствие лишних данных.
Ошибки не включают пути, конфигурацию, credentials или исходный stderr ядра.

Выделенный worker UID не получает право исполнять root-owned memfd через путь:
launcher копирует проверенный image в собственный sealed BinarySnapshot с
проверкой SHA и бюджетом. Config также неизменяемый. Run заменяет launcher
через exec; PID сохраняется, stdin — config FD, argv фиксирован для engine,
среда очищена, stdout/stderr подавлены. Пользовательские SSL_CERT_* не наследуются.

Check запускает version/config-check без runtime сетевых capability и отвечает
Checked только после успеха. Run отвечает Accepted перед exec; это не Applied
и не подтверждение TUN/сети. Нужны проверка unit/PID/invocation и actual health.

## Фиксированные units

Один helper владеет одной глобальной системной сессией. Используются фиксированные
`yonik-worker.service/socket` и `yonik-worker-check.service/socket`, системный
пользователь yonik-worker. Socket root:root 0600, каталог 0700. Входной listening
socket передаётся через StandardInput=socket; launcher принимает соединение через
безопасный rustix accept, без raw FD conversion и unsafe. Этот способ описан в
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

Check: zero capabilities и PrivateNetwork. Run: bounding/ambient NET_ADMIN,
доступ к /dev/net/tun через DevicePolicy=closed и точный DeviceAllow; полный root
не выдаётся. NET_ADMIN остаётся сильной привилегией на netns, не sandbox.
Ограничены filesystem/home/namespaces/devices, память, задачи, core dumps и
наследование привилегий. Оба service/socket связаны с lifecycle helper.
Существующий helper unit не ослабляется до готовности его TUN-интеграции.

## Supervisor и восстановление

Supervisor использует только canonical system bus и проверенного root-владельца
org.freedesktop.systemd1. Доступны только фиксированные units, режимы и socket
пути. Проверяются installed unit contract и D-Bus properties; произвольные
drop-ins, transient или изменённый контракт отклоняются. WorkerTicket привязан
к MainPID и ненулевой InvocationID, а не одному PID.

Pending state и blocking FD-transfer handle сохраняются внутри владельца до
await. Отмена/timeout не превращают незавершённую передачу в чистое состояние;
recover завершает её перед разрешением нового старта. Stop сначала закрывает
socket activation, затем останавливает service и требует подтверждения пустой
cgroup v2 (populated=0 либо доказанное отсутствие собственного каталога).
Одного inactive/MainPID=0 недостаточно. При неизвестном состоянии сеть очищать
нельзя; caller сохраняет recovery-required и выбранную kill-switch защиту.

Manager API не предоставляет атомарный compare-invocation-and-stop: проверка
ticket перед StopUnit защищает от уже наблюдаемой замены, но гонка с другим root
администратором не обещается. [Контракт systemd D-Bus](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html).

## Приёмка и открытые границы

Private-bus tests проверяют сериализацию, fixed targets, смену invocation,
сохранение незавершённой передачи, stop order, cancel и отказ при непустой
cgroup. Canonical namespace gates проверяют actual FD launcher обоих ядер,
отличный от helper/TUN owner ненулевой UID, zero-capability Check и TUN/RPDB
traffic с NET_ADMIN-only Run, без loopback
обхода mark. Они не заменяют запуск установленного unit с выделенным UID,
реальным systemd hardening, SIGKILL helper и всем cgroup tree.

Далее нужны SystemSessionHost, типизированный profile Prepare, одноразовый
artifact, политики Apply/Stop/recovery, controller и GUI. До этого ни unit-файлы,
ни успешный протокольный тест не считаются готовым пользовательским VPN.
[Evidence и ограничения](../validation/2026-11-10-worker-runtime.md).
