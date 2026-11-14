# P02: минимальный план доверификации после 0a8bc5e

Это предложение для независимого root-review, **без нового запуска**. Рекомендация:
разрешить переиспользование bounded observational evidence старых окон и заменить
только matched pair sing-box №2 двумя новыми окнами full→engine по 900 s. Старые
данные сохранить отдельно. После этого — review объединённого компонентного
набора, не автоматическое объявление полного P02/release/energy acceptance.

## 1. Что уже установлено и чем это отличается от новых guards

Measurement source — 35408d5; 12 окон, 372 rows (31 на окно), 6/6 пар с одинаковыми
actual config bytes внутри пары. Validator source 51fd15a проверил каждый row,
включая reference row: тот же набор PID, starttime, namespaces, неизменные
transitive descendants и отсутствие descendants вне учтённой группы. Ошибок нет.
Таким образом, в **сохранённых snapshot points** нет свидетельств PID подмены,
namespace drift, второго engine или неучтённого product child.

Из старого lifecycle trace и завершения driver установлены Connected→hide→Stop,
pidfd exit readiness после Stop, rebind SOCKS, отсутствие детей после Stop,
закрытие GUI, successful Popen.wait и campaign exit 0. При финальной проверке
сохранённые product PID/starttime больше не жили; cleanup-fallback/failure.json
отсутствуют. Pin executable и config binding проверены отдельно от rows.

Новые 51fd guards не меняют product ELF, config/compiler или сценарий. Они
удерживают pidfd известных процессов весь idle, следят за exit readiness во время
ожидания и проверяют identity/exact group перед сохранением каждого sample.
Старая кампания переоткрывала pidfd между интервалами и не применяла validator
синхронно. Posthoc не доказывает исполнение новых guards, lifetime владение pidfd,
fail-fast при нарушении, которое тогда могло остаться незамеченным, и не может
восстановить отсутствующие samples. Ни старые, ни новые snapshot checks сами по
себе не исключают неизвестного ребёнка, родившегося и исчезнувшего целиком между
30-секундными samples: это не process-spawn tracing.

Отдельные 51fd short controls закрывают другой вопрос — чувствительность oracle
и cleanup: actual GUI wrong-CA→Limited/kind=tls/noHTTP, trusted-positive, actual
pinned engines SIGSTOP+controlled driver abort→TERM→KILL/exit/reap/rebind. 6 tests
PASS. Это не ретроактивное исполнение guards старых окон и не production GUI
cleanup_fault API. Повторять эти неизменённые controls не требуется.

**Review decision R-A:** достаточно ли этих фактов для переиспользования старых
окон именно как bounded component measurements? Если нет и требуется held-pidfd
во всех long windows, одна replacement pair этого не исправит. Нужно вернуть
точный расширенный scope root, а не молча запускать 12 окон заново.

## 2. Известный noise и его пределы

Targeted commands исполнялись 2026-11-14 01:05:09.309–01:07:37.646 UTC:
148.337 s. Для sing-box-2-full это примерно offsets 55.04–203.37 s из 900 s,
то есть 16.482% длительности. Offset anchor выведен из final samples.json mtime
минус last elapsed; per-row wallclock не записан, поэтому offsets приблизительны.
Интервал включает setup/teardown и тесты, а не только CPU-active фазу controls.

Наблюдаемые точки суммарной product group:

| Elapsed, s | PSS, KiB | Private dirty, KiB | CPU ticks |
|---:|---:|---:|---:|
| 30.03 | 141645 | 97124 | 255 |
| 60.06 | 121250 | 97124 | 255 |
| 90.09 | 140619 | 97124 | 255 |
| 210.21 | 140767 | 97252 | 255 |
| 900.02 | 142404 | 98012 | 258 |

PSS в ~60 s ниже предыдущего sample на 20395 KiB (19.92 MiB); затем возвращается
близко к прежнему диапазону. Это совместимо с перераспределением PSS общих ELF/
библиотечных страниц при запуске дополнительных GUI, но mapping-level samples
не сняты: причинность и величину коррекции этим не доказать. CPU group ticks
между ближайшими окружающими samples ~30–210 s не изменились. Это не доказывает
отсутствие host scheduling/cache/thermal влияния. Endpoint снят примерно через
697 s после окончания controls, но отсутствие retained effects не установлено.

Нельзя вычесть 148 s, усреднить оставшиеся samples как новый 900 s run или
применить поправку 16.482% к CPU/PSS. Численный upper bound bias не установлен;
измерено время воздействия и raw отклик, а не контрфактический clean baseline.

Исключение только full №2 оставляет **две** sing-box full repetitions; из требования
трёх чистых повторений это не делает три. Для основного paired comparison
консервативно исключается вся старая pair №2; её engine half и noisy full остаются
доступными как дополнительные descriptive observations. Старые pairs №1/№3
sing-box и №1/№2/№3 Xray не имеют зарегистрированного overlap этих controls;
это не гарантия отсутствия любой прочей host-нагрузки.

## 3. Сравнение минимальных вариантов

- Только reuse всех старых данных: 0 новых окон, полезный component dataset,
  но известный noisy full остаётся; требования трёх clean sing-box repetitions
  таким решением не закрыть без явного пересмотра критерия.
- **Одна replacement matched pair**: 2 новых окна, 1800 s measurement плюс
  bounded setup/cleanup. При R-A получается 3 retained sing-box pairs и 3 Xray
  pairs без известного targeted-control overlap. Это рекомендованный минимум.
- Новый release baseline: отдельная задача и новый artifact binding, если root
  принимает нормативный release/physical acceptance profile. Не устраняет noise
  старого dev набора и не является необходимым условием его component review.
  Смешивать release и dev repetitions в один трёхкратный baseline нельзя.

## 4. Какой профиль действительно требует spec

[performance.md §5](../specs/performance.md#L61) называет бюджеты
«Цель для первого прототипа», суммарный GUI+core бюджет ещё устанавливается после
измерений (§5, строки 74–76). [§6](../specs/performance.md#L78) требует версии,
питание/governor/сеть и ресурсы; Zenbook AC и battery — отдельно, далее перечисляет
config matrix. [P-02, §7](../specs/performance.md#L95) требует short 15 min и
8h energy, group overhead/отдельный живой tray/один engine/no optional probes.
[§7 release/G-POWER](../specs/performance.md#L107) требует выделенное physical
устройство и закреплённый baseline. [§7 repetitions](../specs/performance.md#L111)
требует минимум три прогона, разброс/условия, near-zero baseline — absolute values.

В этих пунктах **нет явного требования Cargo release/конкретного opt-level** для
short component measurement. Поэтому новый Rust release build сейчас не
обоснован этим текстом. При этом существующий dev/unoptimized GUI + production
pinned engines — именно controlled component measurement на AC/powersave,
offscreen/software Qt/private SNI, не release-budget acceptance. Требования
physical/AC+battery/8h/config matrix остаются отдельными открытыми условиями.
Root должен явно выбрать профиль acceptance, а не назвать dev набор final P02.

## 5. Точная спецификация одного действия после root choice

Машинные параметры и hashes: [minimum-plan.json](../evidence/p02-short-private-20261114/minimum-plan.json).
Все inputs — существующие owned artifacts, не caller server/config:

- cwd: `/home/myrs/.t3/worktrees/yonik/t3-aef0f1a8-4b0e7a90d95fae43`;
- corrected helper source: 51fd15a, `connected_idle.py` SHA256
  `508f837200ffa07aaaca6e88cc296c41dd789bf6dfbd9aa054d6bd8c43536f23`;
- GUI ELF `/home/myrs/projects/yonik/local/evidence/p02-short-private-20261114/yonik-desktop`,
  SHA256 `e3aee54cab750d072dc1f9d075a3c5eb4b0911d96360d834d5680f3bd812e8f8`;
- observer в том же каталоге `observer.so`, SHA256
  `e7c94f3a66b6f6c7d439ea35ca6f0b867170aff4ee0d000a9c45be4b90b092d5`;
- core sing-box `/home/myrs/projects/yonik/local/engines/sing-box-1.14.4/sing-box`,
  pin `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`;
- fresh own output `/home/myrs/projects/yonik/local/evidence/p02-replacement-sb2-reviewed/`;
  ровно один core, одна пара, порядок full→engine, каждое idle **900 s**;
  sampler interval 30 s, оба corrected held-pidfd/group guards;
- существующие https_server/peer/gui helpers: собственные свободные loopback
  ports, тот же logical VLESS LocalSocks/no-app-rules сценарий, RSA2048/CA policy,
  private bus без activation directories, private KSecretD PAM hash 56 bytes,
  subscription key создаёт production SecretService path. Старые числовые ports
  не резервируются повторно вслепую; неизменны allocation policy и logical route;
- full: existing `gui → prepare(sing-box) → actual QAction connect → Connected →
  capture(actual stdin pipe) → hide → idle([GUI, engine],900) → Stop/reap/rebind → quit`;
- engine half: existing `engine_only(sing-box, SAME_CAPTURED_BYTES,900)` на тех же
  peer/HTTPS fixture/ports/CA/environment/keepalive. Перед idle только health warmup.
  Конфиг нельзя компилировать заново для baseline. Новый random probe credential
  допустим; hash обязан совпадать **внутри новой пары**, не с прежними repetitions;
- GUI/renderer/product tray остаются в group; infrastructure отдельно. До запуска
  исключить новые controls/builds этого агента и зарегистрировать условия/overlap;
  чужую host-нагрузку не останавливать. Unknown child/drift/exit/traffic/cleanup
  violation → точный FAIL, без одинакового retry и без удаления noisy artifacts.

**Это спецификация вызовов helper, не готовая measurement CLI.** Stock `campaign()`
запускает все cores/repetitions; `--repeats 1` отклоняется, `--oracle-only` не заменяет
pair. Не использовать эти команды как selector. Если root выбирает R-A + одну
replacement pair, следующий implementation шаг — узкий one-pair entrypoint по
спецификации выше с dry-run default и тестом ограничения количества окон; затем
проверка diff перед единственным разрешённым запуском. Никакой новый runner или
измерение этим документом не запущены. Повторять unchanged TLS/cleanup controls,
строить/download ELF или менять host session/TUN/VM не нужно.

После новой пары reviewer получает старые пять retained pairs + replacement,
весь исключённый raw отдельно, два measurement-source binding и отдельный
validator/control binding. Даже тогда остаются dev/physical/energy/profile matrix,
неполные непрерывные process observations, tick quantization и fixed-order bias.
