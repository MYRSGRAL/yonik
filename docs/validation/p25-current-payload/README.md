# P25: actual payload → notices/source obligations

База leaf: `3247e6c32a5ed83ec5d812dfc1f70695d3f2b3b4`. Это data-only
исследование, не новый freeze и не полный P25 PASS. Применение лицензий и выбор
OR/WITH не выполнялись. Product, builder и исторические inventories не изменены.

## Источники и воспроизведение

Frozen PR181 `8844d221d6b55aa0aade08f214dec3d42269e7d1`:
[result.json](https://github.com/MYRSGRAL/yonik/blob/8844d221d6b55aa0aade08f214dec3d42269e7d1/docs/evidence/a4-mtree4/result.json),
[registry-inventory.json](https://github.com/MYRSGRAL/yonik/blob/8844d221d6b55aa0aade08f214dec3d42269e7d1/docs/evidence/a4-mtree4/registry-inventory.json),
[provenance.log](https://github.com/MYRSGRAL/yonik/blob/8844d221d6b55aa0aade08f214dec3d42269e7d1/docs/evidence/a4-mtree4/provenance.log).
COLLECTED source `14229843f9a11bf98ec4f5992df00f3247102ea2`, tree
`7daa4ebb7cc25d3ceafab76809afc78753dc5ec3`.
PR179 `2599fe70`: `docs/validation/2026-11-13-package-provenance-preflight.md`
и frozen controller описывают локальный TCB, actual package и source validation;
это не воспроизводимость байтов и не юридическая приёмка.
Queue: `/home/myrs/projects/yonik/local/orchestration/linux-remaining-task-queue.md`.
Mutable worktree A4 не использован.

Retained artifact вне TTL:
`/home/myrs/projects/yonik/local/release-controller/linux-controller-rehearsal-14229843-msrv85-mtree4/package.tar`.
SHA-256 `26a013747e4c1dbb95e7290cd37b981f5dc7ef891a8865897f09fc45bacd0237`.
510 regular entries, включая `.MTREE` и `.PKGINFO`; число 508 в Qkk относится
к установленным файлам. [ledger.json](ledger.json) сохраняет каждый entry/hash,
не копирует DB или секреты. Собственного scratch/build нет.

```sh
python3 docs/validation/p25-current-payload/reconcile.py > /tmp/p25-ledger-check.json
cmp docs/validation/p25-current-payload/ledger.json /tmp/p25-ledger-check.json
python3 -m unittest discover -s tools/tests -p test_compile_notices.py
```

Reconciler читает tar без extraction/exec; сверяет package hash, duplicate/type,
398 index entries, 298 уникальных hashes notices, первичные Rust/Go тексты из
frozen source142 Git, source ZIP hashes и frozen inventories. Не заменяет
независимый provenance verifier и не доказывает полноту всех embedded notices.

## Source-bound join

| Actual redistributed слой | Требуемая связь notices/source | Проверенное evidence | Остаток / граница вывода |
| --- | --- | --- | --- |
| `usr/bin/yonik-desktop`, helper, worker; units/desktop/polkit/icon | Собственная LICENSE, точный source и инструкции | LICENSE и `usr/share/yonik/sources/release-source.tar` присутствуют; внутри архива есть `src/packaging/arch/README.md`, RU/EN `src/docs/user/linux-*.md`; entry hashes в ledger | Инструкции включены через исходный архив; пригодность текущих руководств к финальному A5 здесь не проверялась |
| Embedded Rust/native/CXX-Qt | SPDX и первичные LICENSE/NOTICE для реально включённого кода; соответствующий source/patch/build closure | Shipped `inventory.json` byte-identical source142 и accepted3247; все перечисленные Rust/Go text refs проверены по SHA с frozen Git и package | Metadata normal/build union не точный runtime inventory; наличие текстов не доказывает release-source closure/std/native/generated attribution |
| `usr/lib/yonik/cores/xray`, `sing-box` | Первичные core LICENSE, модульные notices, upstream+patched source, patches/toolchain/build данные | Первичные core LICENSE побайтно сверены в `patched.tar:src/LICENSE` с frozen upstream texts (hashes в ledger), отдельно в notices их нет. Actual ELF entries присутствуют; `sources/{xray,sing-box}/{upstream.tar,patched.tar,manifest.json,prebuild.json,source-lock.json}` и adapter patches в том же tar; Go inventory и тексты поставлены. 169 из 173 исторических Go records имеют source ZIP в tar, hashes проверены | Четыре отсутствующих ZIP: purego и три cronet records (полные module names в ledger). Это более широкий historical inventory, отсутствие ZIP само по себе не доказанный missing source фактического ELF; closure binding проверял frozen controller, не новый RE |
| Qt headers/templates/generated C++/QML | Первичные применимые Qt/generated-code условия и attribution, соответствующий source | Сохранён `composition/qt-sources.json` с первичными hashes; 169 уникальных Qt primary hashes отсутствуют в shipped notices index | Это **кандидаты для attribution**, не 169 обязательных недостающих лицензий: inventory включает third-party/tests/alternative licenses. Точный применимый generated/header набор не установлен. Старый checksum RE не повторялся; missing release-source closure отдельно от missing required text |
| Qt DSO/plugins/OS | Условия фактической интеграции; внешняя поставка не равна содержимому YonIk | Entry list не содержит libQt/OS DSO; external dataset не повышен до redistributed payload | Не вводится SLSA/побитовая воспроизводимость каждого OS file как новое требование |
| Notices UI и shipped source statement | Утверждения должны описывать конкретную поставку | SOURCE-OBLIGATIONS и SCOPE byte-identical source142 и accepted3247; NoticesView в accepted Git утверждает отсутствие cores | Ниже конкретное противоречие statement, независимо от полноты source closure |

## Конкретный дефект statement и один следующий шаг

В actual tar одновременно есть `usr/lib/yonik/cores/xray`,
`usr/lib/yonik/cores/sing-box` и `usr/share/licenses/yonik/SOURCE-OBLIGATIONS.md`,
где сказано: «planned Arch package не содержит xray/sing-box и не устанавливает их».
Accepted `crates/yonik-desktop/qml/NoticesView.qml:32` также утверждает
«не включённые в пакет». Это воспроизводимое несоответствие текущей модели
поставки; вывод основан на actual entries, а не ingest/registry observations.
Не утверждается отсутствие MPL/GPL текстов или core source archives.

**ONE minimal remaining final-freeze action:** root-approved current-payload
compliance reconciliation перед финальным A5: заменить текущие UI/source statements
на описание выбранного actual release payload и закрепить его применимый
embedded Rust/Qt/native notices/source closure в final package manifest, затем
проверить actual freeze тем же entry/hash join. В рамках этого шага явно разрешить
недоказанный Qt generated/header attribution, а не объявлять весь historical Qt
inventory обязательным и не повторять checksum RE. До такого reconciliation
полнота release-source closure остаётся OPEN; конкретный установленный дефект —
ложное statement об отсутствии cores. Product/builder изменения требуют root
approval и здесь не выполнены.

`composition/P25-SCOPE.md` явно исторический package78/source eec7 и не latest;
его историю и старое утверждение об отсутствии notices у package78 исправлять
нельзя. Реальный package142 уже содержит notices. Собственный GitHub URL не
назван отдельным письменным source offer: actual source archives оценены отдельно.
Final A5, legal policy/OR/WITH, новые сборки/установка/VM/network research не делались.

Проверки: replay reconciler; 5 compile-notices unit tests PASS. Никаких
Rust/Go/C++ builds, engine exec, keyring/service operations или новых зависимостей.

Ruff отсутствует в PATH; установка не выполнялась. Reconciler — исследовательская обвязка конкретного retained tar, не новый production validator.

## Delta после frozen c005b53

Новые statements изменены отдельным коммитом по разрешению root; ledger.json
и его source142/accepted3247 comparisons остаются историческим свидетельством
package142. Текущие SOURCE-OBLIGATIONS/NoticesView не приписываются старому tar.
В source нет `packaging/licenses/SCOPE.md`: `tools/compile_notices.py` копирует
`packaging/licenses/composition/P25-SCOPE.md` в `usr/share/licenses/yonik/SCOPE.md`.
Actual shipped SCOPE уже проверен reconciler как byte-identical frozen source.
Дополнение по Qt и точный незакрытый attribution gap: [qt-join.md](qt-join.md).
