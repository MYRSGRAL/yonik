# RPDB системной TUN-сессии — 10 ноября 2026

База: PR #37 влит как `e9c4c1e6c6935c13a8e842374817a9cd7771b1bc`.
Все пять jobs обоих workflows прошли на `8a148c2` перед merge.
Кандидат: ветка `feat/system-tun-rpdb`.

## Проверенный результат

- Новый TunRule executor и durable Resource::TunRule; фиксированные invert,
  mark/full-mask/protocol, parent anchor и только confirmed собственные routes.
- Создание через CREATE|EXCL; Intent/reopen/confirmed-absent не присваивают
  неизвестный объект. Полная сверка kernel selectors перед подтверждением.
- Cleanup rule до route, затем address/TUN. Generic cleanup не вызывает Route
  callback при наличии зависимого rule; parent сохраняется при остатках.
- Canonical `tun-rule`: actual IPv4/IPv6 lookup, marked bypass через обычную
  main table, reopen, unknown intent, foreign priority/selector/table reference,
  потеря own default route и подтверждённый обратный cleanup.
- Compiled Xray и patched sing-box: отдельный peer netns за veth, default routes
  в собственной таблице и реальные journal-backed rules. Unmarked route-get
  выбирает TUN, mark 99 выбирает veth. TCP/UDP IPv4/IPv6 проходят TUN→VLESS→echo;
  без peer обмен не проходит. После SIGKILL клиента удалены собственные rules,
  routes, addresses и TUN, журнал пуст.
- Peer использует RFC1918 endpoint `10.203.0.2`: Xray compiler штатно отвергает
  plaintext VLESS к публичному адресу, поэтому первая fixture с benchmark IP
  была отклонена UnsupportedSecurity. Продуктовая проверка не ослаблялась.

## Проверки

- Rust workspace: **468 passed, 0 failed, 17 ignored**, 44 suites.
- fmt и workspace clippy all-targets с `-D warnings`: PASS.
- Python: **115 tests**, Ruff 0.17.4 format/check всех tools: PASS.
- Восемь actual namespace gates: owned-tun, tun-config, tun-rule, public-block,
  durable-policy, service, compiled Xray, compiled sing-box: PASS.
- YAML разобран, bash -n для четырёх явно заданных bash steps: PASS.

Все сетевые эффекты были в собственных user/net/mount/pid namespaces;
компилированный peer дополнительно изолирован в соседнем netns. Host netns
проверен до эффектов. Helper/worker service не установлен и не запущен на host.
Использованы только статические синтетические credentials; пользовательские
подписки, HWID и секреты не читались.

Логи: `local/validation/rpdb/`, включая final-workspace-tests.log,
final-workspace-clippy.log, namespace-*.log и compiled-*-private-peer.log.

## Ревью и исправления

Независимое ревью нашло P2: повторный ensure после исчезновения default
возвращал ошибку до сброса старого reconciled. Namespace regression сначала
воспроизвела дефект (`review-regression-red.log`), затем прошла после сброса
подтверждения перед первым await/snapshot (`review-regression-green.log`).
Узкий повторный review не выявил новых findings. Во время runtime проверки
учтён kernel sentinel FRA_SUPPRESS_PREFIXLEN=u32::MAX: это отсутствие suppress,
реальные suppress selectors и неизвестные attributes остаются запрещены.

Дополнительно воспроизведён отказ cleanup после перевода родителя/маршрута в
CleanupRemaining (`cleanup-state-red.log`). Удаление теперь принимает это
состояние с прежними exact ownership проверками; создание по-прежнему требует
Confirmed. Regression прошла (`cleanup-state-green.log`), узкое ревью не нашло
новых замечаний. Отдельно проверены две семьи rule в CleanupRemaining до
первого удаления (`both-cleanup-green.log`).

## Границы

Это необходимые executor и runtime gates, а не готовый пользовательский VPN.
Registry/worker/systemd/session host/IPC/controller/GUI ещё интегрируются по
[плану](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-system-session-integration.md).
system_tun capability остаётся false. DNS/Fake-IP, private VPN/LAN/reconcile,
полная Linux-матрица и поставка не закрыты. P12/P13 остаются частичными;
итог общего плана — **3/26 (11,5%)**, полностью закрыть осталось 23 пункта.
