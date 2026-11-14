# Офлайн producer кандидата N5

`n5_build_manifest.py` не собирает и не запускает ELF, не запрашивает ядро,
не использует сеть, не подписывает, не устанавливает и не регистрирует профиль.
Результат всегда **UNREGISTERED / NOT_ADMISSION**. Регистрация остаётся закрытой.
Контракт sidecar соответствует schema 1 native_profile (`41ea289` с обязательным
`kernel_build_id` из `b335a44`).

Из корня checkout:

```sh
python tools/n5_build_manifest.py \
  --worker retained/worker.elf --source retained/source.tar \
  --receipt retained/trusted-build-receipt.json \
  --provenance retained/pinned-provenance.json \
  --output candidates/n5-new
python -m unittest discover -s tools/tests -p test_n5_build_manifest.py -v
```

Родитель выхода должен уже существовать, принадлежать текущему uid и находиться
в текущем workspace без symlink-компонентов. Сам каталог выхода должен быть новым.
Системные пути запрещены даже при запуске из них. Выход: `deployment.json` и
отдельный `report.json`. Файлы публикуются через exclusive hard-link после fsync,
каталоги также fsync. Существующие файлы не заменяются. Два файла не являются общей
транзакцией: при сбое возможен неполный каталог, который нельзя использовать;
повторять следует с новым именем выхода. Никакой результат не даёт admission.

Доверенную квитанцию предоставляет вызывающая сторона из проверенного build
pipeline. Producer не устанавливает её подлинность: произвольная пользовательская
квитанция не становится доверенной от успешной проверки. Все значения ниже —
**иллюстративные**, для настоящих артефактов нужны их фактические SHA-256:

```json
{"schema":1,"worker_sha256":"1111111111111111111111111111111111111111111111111111111111111111","source_archive_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}
```

Независимо закреплённый provenance передаётся как DATA, не извлекается с хоста:

```json
{"schema":1,"policy_id":"yonik-own-namespace-fixed16-v1","policy_sha256":"3333333333333333333333333333333333333333333333333333333333333333","kernel_release":"6.12.1-example","kernel_machine":"x86_64","kernel_abi":"linux-native-abi260-ynkch004-ynkns004-v1","kernel_build_id":"4444444444444444444444444444444444444444"}
```

Все поля обязательны, неизвестные и повторные поля запрещены. Хеши — точный
lowercase hex64, build ID — lowercase hex40 (20 байт), нулевые значения запрещены.
В sidecar хеши представлены массивами 32 байт, build ID — массивом 20 целых байт,
а `kernel_machine` имеет именно это имя. Kernel release: 1–128 ASCII символов
`A-Z a-z 0-9 . _ + -`. Значения policy ID, machine и ABI фиксированы.
Policy SHA отражает фактическую закреплённую deployment policy и не подменяется
хешем frozen control `bd5d7474108a2a1e051734ea4c9097d43380341025ed9cd60e0f1442527d2983`.
Последний присутствует только как отдельно обозначенная reference в отчёте.

ELF и source должны быть сохранёнными ненулевыми обычными файлами, до 128 и
512 MiB соответственно. Проверяются ELF magic, SHA-256, identity/размер/mtime/ctime
до и после чтения и повторное открытие pathname без symlink. JSON ограничен
4096 байтами, выходные файлы тоже. Архив не распаковывается, ELF не исполняется.
Хеши подтверждают совпадение байт; связь source→ELF утверждается исключительно
внешней доверенной build-квитанцией, а не является доказательством компиляции.
Старый control source нельзя переименовать и считать новым build artifact.
Доверенная квитанция и provenance остаются внешней TCB; тесты используют синтетические
ELF-magic fixtures, которые ничего не доказывают об installed campaign.

Python API: `produce(worker, source, receipt, provenance)` возвращает пару
`(strict_sidecar, separate_report)` без записи; `emit(output, sidecar, report)`
публикует кандидаты. CLI возвращает 2 при ошибке проверки или файловой операции.
