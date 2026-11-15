# P14: oracle v1 — SYNTHETIC_REFERENCE

Полный P14: **NOT PASS**. Это test-only leaf на базе
`099db2a4ef9d799fcdaf3b3fbd2eb83cbe5a110a`, без новых gates,
capability/admission и без runtime authority.

Корпус: `tests/fixtures/p14-policy-plan-oracle-v1.json`.
Rust consumer: `crates/yonik-engine/tests/p14_plan_oracle.rs`.
Норматив: `docs/specs/networking.md`, раздел 5, и
`docs/specs/validation-and-roadmap.md`, D-01…D-07.

## Формат для будущих consumers

Обычный UTF-8 JSON, version=1, classification=SYNTHETIC_REFERENCE.
Числа в этом корпусе малы и точно представимы будущим Go consumer;
при расширении epochs/IDs следует декодировать в uint64, без float64.
`profiles` содержит явные полные expected DATA-документы. Rust независимо
строит typed Policy/DnsPolicy/DesiredPlan для каждого именованного профиля,
компилирует в bytes и сравнивает весь JSON: policy, DNS, requirements,
порядок правил, desired bindings, bounds и epochs. Сравнение структурное:
порядок ключей JSON не является семантикой; порядок массивов сохраняется.

`cases` ссылаются на профиль и содержат отдельные `observation` и `expected`.
Observation никогда не включается обратно в desired DATA. `available` в
emitted policy — сериализованный snapshot входа, не live свидетельство VPN.
`epoch` observation — поколение ответа, context epoch читается из emitted
`desired`. `now` и `expires_at` — синтетические монотонные ticks.
`path=0` означает policy resolver; остальные значения — VPN ID.
`a`/`aaaa`: answer, nodata, timeout, servfail, unqueried.
`resolution`: answer, failed, missing. Это вход reference API, не DNS пакет.
`mapping`: none, valid, expired, stale; synthetic fake address — 198.18.0.1.

Typed expected outcomes: decided (route, origin, vpn), rejected (error),
need_resolution (vpn). VPN 0 означает отсутствие VPN; это не настоящий ID.
Ошибки `dns_policy_ambiguous` и `dns_policy_unresolved` соответствуют
нормативным DNS_POLICY_AMBIGUOUS и DNS_POLICY_UNRESOLVED;
unknown_fake_mapping соответствует PolicyFault::UnknownFakeMapping;
wrong_resolver — PolicyFault::WrongResolver.
Expected outcomes записаны явно, не вычисляются evaluator-ом.

## Покрытие и границы

D-01: приватный CIDR старше личного proxy, VPN доступен/отключён.
D-02: личное правило старше preset CIDR. D-03: первое any-match правило
для всего RRset и отдельный literal IP. D-04: private/public и два VPN.
D-05: timeout/SERVFAIL, partial family, одно/два NODATA. D-06: внутренняя
зона отключена, запрос после возврата VPN и ответ его resolver.
D-07: граница expiry, каждый epoch, неизвестный/просроченный/stale/valid fake.
Каждый RRset повторяется с обратным порядком; два адреса дают все перестановки.

После полного golden-сравнения тест восстанавливает Policy из emitted
представления и вызывает существующий `Policy::evaluate_destination`.
Декодер переносит поля; собственной реализации приоритетов/DNS engine нет.
Reference family aggregation: answer/NODATA завершают семейство, ошибка — нет.
Публичный API сводит family outcomes в `AnswerSet.complete`, а timeout и
SERVFAIL — в `Resolution::Failed`. Реальные запросы/пакеты не проверяются.
DNS fields и requirements проверены как DATA; они не исполняют runtime.

В `missing` явно сохранены NOT_IMPLEMENTED seams: независимые family error
classes на runtime boundary и allocator/persistence/nonreuse/revoke sockets.
Также не доказаны CNAME/min-TTL, trusted binding перед dial, фактическое
отсутствие публичных DNS-запросов, ограничения concurrency/deadline и интеграция
с обоими ядрами. NeedResolution не доказывает выполнение lookup.

Consumer ограничен 128 KiB JSON, 64 cases, 10 profiles, 64 адресами на case,
253 bytes на имя; production DATA имеет собственные bounds. В частности,
emitted answers=256 не расширяет существующий reference limit=64.
Unknown поля envelope/case/observation и expected outcome отвергаются;
полные profiles проверяются точным golden-сравнением. Negative tests проверяют
неизвестное поле, неизвестный вид входа, несогласованное семейство, oversized
corpus/RRset, повторный rule ID и unknown desired authority.

## Воспроизведение

Rust 1.85.1, locked/offline, -j1, только test `p14_plan_oracle`.
Сборка через `/home/myrs/projects/yonik/local/orchestration/with-rust-slot`
под BSD lock task root `/var/tmp/codex-myrs/transient/n5-p14-oracle`,
CARGO_TARGET_DIR внутри этого root. DBUS/XDG окружение не меняется.
Evidence (исходники, ELF, SHA256 и логи) сохраняется вне TTL в
`/home/myrs/projects/yonik/local/evidence/n5-p14-oracle`.
Никакие core/worker/Host, сеть, Go или Docker не запускаются.


## Corrections после R2

Корпус содержит 28 cases и 9 profiles. Добавлены ровно пять векторов:

- `D-01/fake_private_available`: valid fake mapping и реальный private RRset
  дают private_vpn, private_network, VPN 7.
- `D-01/fake_private_unavailable`: те же mapping/RRset при недоступном VPN
  дают block, private_network, без VPN.
- `D-07/fake_private_public_ambiguity`: valid mapping не скрывает смешанный
  private/public RRset; ожидается dns_policy_ambiguous.
- `D-06/fresh_policy_wrong_resolver`: fresh full answer внутренней зоны
  с Policy resolver path даёт wrong_resolver.
- `D-06/fresh_wrong_vpn_resolver`: тот же ответ с VPN 8 вместо VPN 7
  даёт wrong_resolver. Контроль `D-06/private_answer` сохраняет успех VPN 7.

Новые fake profiles содержат одновременно desired fake pool/mapping lease
и private VPN bindings; весь DATA golden проверяется до реконструкции Policy.
Новые векторы, как остальные, проверяются в обоих порядках RRset.

Для corrections evidence создаётся отдельно в
`/home/myrs/projects/yonik/local/evidence/n5-p14-oracle-r2/<exact-SHA>/`.
После локального коммита `git archive <exact-SHA>` сохраняет полный tracked
source archive вне TTL. Frozen build использует только этот архив, включая
canonical tracked Cargo.lock, а не изменённый рабочий lock. До исполнения
pure tests сохраняются source/lock hashes, exact commands, rustc/cargo
metadata и ELF с SHA256. Финальная проверка source manifest подтверждает,
что build не изменил frozen sources. Старое evidence a185 не является
full-source binding нового SHA. Full P14 по-прежнему NOT PASS.
