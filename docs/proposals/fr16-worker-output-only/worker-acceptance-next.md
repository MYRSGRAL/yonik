# FR16 worker: bounded acceptance proposal после PR211/root union

Статус: PROPOSAL / NOT AUTHORIZED / NOT EXECUTED. Новый runtime PASS отсутствует.
Этот документ не запускает VM, worker, engine, systemd, установку или crossUID.
PR213 на source `0bb3e86e22d7bf6709c90453e9f8619b60a59ee4` ещё не accepted:
его CI/review/runtime не являются FR16 evidence этой ветки.

## Source и существующие доказательства

- FR16 reviewed source `4d98b6ef2e05b822085b55b07d4ca7028adc3394`,
  независимый R1 `1c7a98b4`: scoped CLEAN только frozen4d98.
- Ordinary union `11557271eb57ede0e9aa527278a2271fd6c1de6c`, второй parent
  `0bb3e86e22d7bf6709c90453e9f8619b60a59ee4`, без rebase/force.
  `root-union.json` фиксирует FR16 blobs и hash полного списка 535 путей: только backend требует объединённого
  review; прочие изменённые файлы побайтно совпадают с соответствующим parent.
- P11 historical source, reviewed updates и history сохранены. Новый backend
  записан отдельно в `pending_source_updates`, review пустой/pending=true.
  Gate продолжает использовать прежний reviewed blob и обязан быть RED до root
  review. R1 FR16 не превращается в review объединённого P11 backend.
- Historical evidence `/home/myrs/projects/yonik/local/orchestration/evidence/fr16-output-6476/manifest.json`
  относится только к 4d98: 48 own pipe/private-bus/codec тестов; actual worker=false.
  Unit ELF SHA256 `b8b76508cc9313945bb5efc42baa4d366f618800d3c42c0749c44d8f46c8ac1f`,
  private-bus ELF `1739763aeb276bc786ab60a4f4b08ee9ca0e28f1bff85475cad84a8dd2168703`.
  Это не yonik-worker/helper/desktop ELF объединённого source. Старые архивы,
  логи и manifest не перезаписываются; root213 evidence также не перепривязывается.

## Предварительные blockers и pins нового witness

До USER grant нужен новый immutable manifest и root exact-argv review. Сейчас
ELF объединённого source **не собран**, runtime harness ниже **не реализован**.
Обязательные поля, без null/placeholder при разрешении исполнения:

1. Полный accepted/reviewed execution source commit/tree; SHA256 source archive,
   Cargo.lock и список blob изменённых production файлов; source pre/post hashes.
   После добавления witness кода нужен новый scoped review и freeze. Commit этого
   документа не подменяет source будущего witness.
2. Rust 1.85.1, locked/jobs1; features отдельно для product и witness; SHA256 и
   build-id точных yonik-worker, helper, desktop, witness ELF, их динамических
   библиотек и unit/socket/polkit/sysusers files. ELF и source/log сохраняются
   вне TTL до исполнения. Никаких замен ELF после фиксации argv.
3. Pinned Xray 26.10.31 и sing-box 1.14.4: exact ELF SHA256 из проверенного
   guest TrustedRegistry manifest, provenance/signature пакета и actual file hash.
   Одного version string недостаточно. Не выбирать сторонний native adapter
   по совпадению версии и не менять registry pins ради GREEN.
4. Уже существующая signed VM base (reference, не новая проверка подписи):
   `/home/myrs/projects/yonik/local/validation/vm-base/Arch-Linux-x86_64-cloudimg-20261101.620452.qcow2`,
   SHA256 `794eb4889b39e1f0ed7d5ae998b2a1ed2137db8cf8c3476cf2962c7437ecb003`;
   `.qcow2.sig` SHA256 `3dbdf7ffdc95654c47f5262df531dfa563733c72047915eff1245985f030b018`;
   signer fingerprint `1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F`.
   Источник pins: [исторический readonly-inputs.json](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/design/a4-package-hook-proposal-142/readonly-inputs.json).
   До нового boot перепроверить signature/base hash; base readonly, один собственный
   overlay, отдельные vars/seed; не продолжать прежнюю работающую VM без grant.
5. Manifest гостя: image/kernel/systemd/dbus версии и hashes, fixture UID,
   точный адрес guest bus, namespace/cgroup/mount topology, ограниченные loopback
   endpoint/config hashes, unit configuration hashes; без секретов и raw config.

Production helper сейчас публикует system_tun=false. Нельзя поднять этот флаг,
подменить admission, добавить N5 caller/issuer/factory или вызвать unauthorized
start_authorized ради acceptance. Если существующий admitted legacy caller
недоступен в выбранной VM, полный desktop→helper→systemd witness BLOCKED.
Отдельный worker-v3 fixture можно предложить и разрешить как leaf witness,
но он не доказывает production admission или полный FR16.

## Разделение двух сред и command shape

[Историческая fixture `a4_private_system_bus.py`](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/tools/a4_private_system_bus.py) — пустой own-UID system-type bus
без manager/helper/activation. Он годится для отдельной transport-negative lane,
но не может доказать systemd invocation/cgroup-empty. Не выдавать его за guest
system bus. Для полного worker lane нужен настоящий PID1 и system bus **внутри
собственного guest**, с canonical worker units и отдельным review разрешений.
Host `/run/dbus/system_bus_socket`, polkit, службы и registry не затрагиваются.
Не применять DBUS_SYSTEM_BUS_ADDRESS override к production helper: он использует
фиксированный bus path. Private-bus fixtures подключаются явно своим API.

Ниже только схема argv для ещё не реализованного runner, не существующая команда:

```text
<reviewed-launcher> --base <pinned-readonly-qcow2> --overlay <own-overlay>
  --seed <pinned-seed> --vars <own-vars> --network loopback-only
  --guest-manifest <immutable-json> --deadline-seconds 900
<reviewed-guest-runner> --manifest <same-json> --case <one-case>
  --engine <xray|sing-box> --deadline-seconds 60 --output <own-evidence-case-dir>
```

Root должен заменить каждый metavariable точным executable/path/hash/argv,
зафиксировать SSH/serial channel и гостевые UID, разрешённые unit names/actions,
mount/cgroup bounds и cleanup argv. Shell eval, произвольные FD/log paths и
скрытая установка запрещены. No runner invocation до отдельного USER grant.

Bounded matrix: по одному success, cancel-before-send, cancel-after-send,
late-generation+Stop на каждый engine: 8 кейсов, без автоматического retry.
Private-bus badFD/owner/stale/replay/JSON/count controls — отдельный own-process
fixture, не способ получить systemd authority. Общий лимит 15 минут; каждый
case 60 секунд, Stop/cgroup cleanup до 15 секунд; timeout означает UNKNOWN/FAIL,
а не PASS. После первого неизвестного stop новые Apply не выполнять.

## Oracles, обязательные для нового acceptance

| Кейс | Положительный результат и отрицательный контроль |
| --- | --- |
| Success каждого engine | Реальный canonical worker запускает pinned engine в той же systemd invocation, куда helper единожды отправил v3. Сопоставить nonce invocation/ticket, PID/start time/cgroup и FD dev/inode roles без выдачи новой authority. Хотя бы одно ожидаемое native сообщение из frozen четырёх шаблонов проходит Input→typed EventLog→Desktop Page. Wrapper lifecycle, ACK и EOF отдельно не доказывают exec, сеть или stop. Suppress-output control обязан лишить native oracle PASS. |
| Cancel до send | Нет ApplyOutputV1/effect, consumed/drop закрывает обе пары; повторное применение того же Prepared невозможно. Cancel не превращается в native acceptance. |
| Cancel после send | Сначала transport/server принятие, затем cancellation; вызывающий видит Unknown/Cancelled. Ровно один Apply/SCM handoff, никакого legacy downgrade/resend. Helper сохраняет worker/journal custody до независимого worker-first cleanup; поздний ACK не меняет outcome на verified. |
| Late generation | Во время drain G1 сменить UI ProfileRevision на G2; bounded хвост G1 остаётся в исходном immutable context G1, partial stdout и stderr не склеиваются. Новый Apply G2 разрешён только после подтверждённого Stop G1, без параллельной worker admission. Отдельный own-pipe fixture удерживает два scoped reader contexts и доставляет G1 после создания G2; это synthetic timing evidence, не actual-engine evidence. EOF/unknown bytes не порождают native G2 event, handles/writers не перепривязываются. |
| Stop | При flood/неполном frame/stalled disk offer Stop остаётся responsive (контроль UI/actor heartbeat ≤250 ms, отдельно cleanup budget). Подтвердить worker-first termination, cgroup-empty и завершение blocking transfer; при unknown stop сохраняются custody и отсутствие Closed ACK. Затем actual reader/task drain, queue/disk consumer drain; только после этого Closed ACK. Если deadline не выдержан, фиксировать FAIL без ослабления budget. |
| Numeric disk/export | На captured source читать numeric disk v1 (прежние 9 fields/192 cap), валидировать code/source/value/context. UI/copy/save/export показывают только typed projection; raw native bytes и config не попадают в body/control/export. Native expected event должен отсутствовать при producer-suppression control. |
| Canary/bounds | Уникальные небоевые canaries в fixture secret/config и unknown output; fragmented/oversize/partial/invalid-version streams. Проверять отсутствие canary/raw URI/control sequence во всех persisted journal/export/UI/runner outputs; unknown/rejected/drop counters растут. Не собирать raw stdout/stderr в diagnostic log для доказательства. Valid native template остаётся доступным рядом с canary. |
| Cleanup | Нет живых своих worker/engine descendants, nonempty cgroup, sender FD copies, readers, bus tasks и guest forwarding; numeric consumer drained. Нет изменений host units/package/registry. Сохранить evidence вне TTL; завершить свою VM, закрыть собственные sockets/forwards и root-directory flock, штатно очистить собственный target/overlay после сохранения receipts. Unknown cleanup оставляет точный quarantined path/size и блокирует PASS. |

## Явные отдельные USER privileges перед исполнением

Текущий scope этих прав **не выдаёт**. Запрашивать только после review точного
manifest/argv, конкретными действиями, а не общим «можно тестировать»:

- Однократный boot/stop собственной signed disposable VM, собственный overlay,
  serial/SSH transport и loopback-only forwarding, явные лимиты ресурсов/времени.
- Сборка frozen witness/guest ELF (если понадобится), использование shared Rust
  slot и root-directory flock; staging точных файлов в guest. Host install запрещён.
- Guest-root setup canonical units/пакетов/registry/polkit и start/stop только
  перечисленных helper/check/run units; это отдельное разрешение, не обычный тест.
- Если canonical helper(root)→yonik-worker UID→fixture user требует crossUID,
  необходимо отдельное явное разрешение именно на эти guest UIDs и операции.
  До него crossUID полностью запрещён; same-UID fixture не заменяет этот proof.
- Guest TUN/CAP_NET_ADMIN, namespace/cgroup наблюдения и guest loopback engine
  probes — только в точно указанном guest scope. Host capabilities, ptrace,
  network probes, system services и изменения N5 admission не разрешаются.
- Отдельное разрешение на synthetic late-byte/flood/cancel controls с конкретным
  harness и лимитами; не подключать arbitrary FD injection к production API.

До выполнения всех prerequisites итог остаётся SOURCE/PROPOSAL ONLY.
Ни root213 runtime, ни historical 4d98 тесты не присваиваются этому union head.
