# Completion API: состояние реализации

Это частичный SOURCE результат, не завершение P5 и не runtime acceptance.
Production issuer, delivery/custody, versioned backend dispatch, native DAT
delivery, новый resolver snapshot и dynamic firewall lifecycle пока не реализованы.

## Закрытая проекция carrier

`ProfileIntent::project_branch(subject: &str, input: WireNetwork,
mux_worker: bool) -> Result<BranchProjection<'_>, ProfileCompileError>` вычисляет
P→D→C из private typed fields того же intent. `WireNetwork` использует TCP=6,
UDP=17. `BranchProjection` имеет только getters `dial`, `carrier`,
`active_stream`, `action`, `next_subject`; публичного конструктора нет.
`WireAction` соответствует mapping v3: PhysicalStatic=1, Chain=2,
DirectDynamic=3, NoDial=4. Результат заимствует intent, не копирует credentials.

`mux_worker=true` означает синтетический TCP input proxy handler. Это вычисление
кандидата, а не доказательство наличия или выбора outbound mux. Capsule builder
обязан отдельно вывести допустимые branches и nextBranchMask по actual native
decision. Для chain следующий input берётся из carrier, а не исходного flow.
Blackhole/DNS не получают общий dial. Raw UDP не использует configured stream.
Exact XHTTP TLS ALPN `[h3]` даёт UDP; смешанный ALPN этого не делает.

## Local launch record

При реализации delivery Local использует отдельный `YNKLOC01`, version=1,
length=192, тот же layout, что YNKEXT01; SCM rights=0. `workerPid@132` и
`workerStart@144` равны нулю до spawn; owner PID/start принадлежат Host.
Остальные binding/manifest поля сохраняются, reserved bytes нулевые.
Это не System proof: mode проверяет потреблённый trusted issuer, не env.
После spawn Host обязан проверить actual child pidfd/PID/start и HELLO;
Go — inherited Host pidfd, sender peer и binding. Frozen records не меняются.

## Следующая интеграция

Нужны shared bounded codec с 11 tables, закрытый builder полного manifest,
Local/System authenticated issuer и реальные callsites. Этот API не снимает
существующий Unsupported и не объявляет native feature доступной.
