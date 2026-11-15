# P25: частичный Rust capture

Точный opt-in вызов после отдельного trusted freeze нового release-id:

```sh
python tools/release_controller.py collect --release-id p25-rust-capture-01 --rust-capture-only
```

Это описание CLI, а не разрешение запускать сборку. В рамках этой реализации
выполняются только Python-тесты с synthetic runner; native builder, Go,
компиляторы, Qt query, ELF, engine, services, VM и activation не запускались.

Контроллер проверяет frozen source/tooling/profile, восстанавливает собственный
source snapshot, выполняет существующие Rust commands и retain pipeline.
Source, ELF и CXX capture records сохраняются с существующими fsync-гарантиями
до `cargo clean` собственного target в `finally`. Ошибка retention/fsync
оставляет target; production wrapper сохраняет task и пишет failure.json.

После Rust retention выполнение останавливается перед native builder,
восстановлением upstream source archives, source offers и упаковкой.
Обязательные A4/native/source gates полного collect этим не выполнены.

Успех означает только `state=RUST_CAPTURED_ONLY`, запись
`rust-captured-only.json`, `final_linux_acceptance=false`. Поля frozen source,
toolchains, controlled_env, commands, elf и build_capture связывают результат
с фактическими входами. Статус MISSING внутри build_capture остаётся MISSING:
частичный результат не доказывает полноту CXX attribution или final Linux.
Нет collected.json, package.tar, payload и утверждения release readiness.

Partial record не читается как full record. Даже перенос его в collected.json
отклоняется проверкой состояния. Повторный partial/full collect того же ID
запрещён: нужен новый trusted freeze и новый ID. Существующие fixed reuse ID
в partial режиме отклоняются как MISSING до запуска команд: старые Rust stages
не объявляются новым capture и не подтверждают полную source/toolchain/env
closure. Нового механизма reuse этот режим не добавляет.

Без флага collect сохраняет прежний полный pipeline и обязательные gates.
Флаг допустим только с collect, произвольных argv/env/command inputs нет.

CXX cwd допускается также для одного точного пакета из frozen `Cargo.lock`
в фиксированном `registry_source_root/index.crates.io-1949cf8c6b5b557f/name-version`.
До вызова проверяются SHA-256 соответствующего локального cached `.crate` против
lock checksum и bytes его regular members против распакованных файлов; одного
`.cargo-checksum.json` недостаточно. Symlink, traversal, неизвестные пакеты,
несовпадения и изменение identity входов до/после вызова отклоняются.
Проверка ограничена выбранным архивом (caps размера и количества members), без
сканирования cache, discovery и compiler fallback. При enrich proof переиспользуется
на пакет внутри одного прохода; staged registry inputs должны быть archive members.
Фактический cwd сохраняется в observed metadata, включая generated `-E` probe.
Schema и format pins не меняются; изменение tooling требует нового trusted freeze
с полным profile hash и новым release-id. Старый failed collect не переиспользуется.

Registry TAR ограничен 64 MiB compressed/decoded; декодирование идёт порциями
во временный файл. До `tarfile` проверяются физические заголовки, cap metadata,
ограниченная цепочка PAX/GNU metadata и полный нулевой хвост после двух конечных
блоков. Sparse-форматы и скрытые записи после end marker отклоняются.
PAX size override и ненулевой payload nonregular-записей отклоняются до разбора:
их семантика могла бы рассинхронизировать смещения предварительного прохода
и `tarfile`. Обычного size header достаточно при заданных caps.
Внутренний `_registry_tar(archive, *, gzip_encoded=True)` возвращает context manager
с `TarFile`; `gzip_encoded=False` предназначен для pinned plain source TAR
с общим `MAX_FILE` cap. Проверка package/path/type остаётся обязанностью consumer.
Новый cap входит в полный profile hash; старые frozen records не изменяются.

### Внутренний observed schema2: closed probes и generated aliases

Изменение SOURCE/Python требует нового freeze полного final profile; selector
остаётся `p25-final-cxx-v1`. Capture03 остаётся DIAGNOSTIC_ONLY: его failed
schema1 records не переписываются и не становятся успешными задним числом.
Acceptance, legal и production admission не повышаются.

Producer классифицирует argv **до** compiler execution. Schema2 CXX record
обязательно содержит `purpose` и `probe`. Закрытый cc-1.11.1 contract:

- `family-query`: ровно `[-?]`, actual exit 1, source proof отсутствует;
- `family-preprocess`: ровно `[-E, <OUT_DIR>/<digits>detect_compiler_family.c]`,
  actual exit 0, snapshot фиксированного cc source с SHA256
  `97ca4b021495611e828becea6187add37414186a16dfedd26c2947cbce6e8b2f`;
- `flag-support`: фиксированный prefix `-O0 -ffunction-sections -fdata-sections
  -fPIC -m64 -march=x86-64 -Wall -Wextra`, один из `/Zc:__cplusplus`,
  `/permissive-`, `/bigobj`, `-Wa,-mbig-obj`, затем ровно
  `-o <OUT_DIR>/flag_check -c <OUT_DIR>/flag_check.cpp`. Source bytes ровно
  `int main(void) { return 0; }`; actual exit 0 или 1;
- `compile` / `other`: обычная семантика; enrich/replay требуют actual exit 0.

OUT_DIR ограничен `release/build/<known-crate>-<16hex>/out` под build root.
Probe source читается NOFOLLOW с FD/type/stat checks, cap 4096 bytes;
pre/post identities проверяются и вокруг runner. Proof содержит source path,
bytes hex и SHA256. Probes не получают dependency flags, unit или depfile,
не увеличивают compiled units; source snapshot доступен replay после удаления
временного family source. Schema1 поддерживается только с actual exit0.

Observed schema2 содержит обязательный `aliases` map (включая пустой).
Обычный Reader остаётся NOFOLLOW. Специальный reader допускает только header
`.h/.hpp/.hxx` внутри generated include forest
`release/build/{cxx-qt,cxx-qt-lib,yonik-desktop}-<16hex>/out/cxxqtbuild/include/{cxx-qt,cxx-qt-lib}/...`.
Максимум 4 symlink перехода, 128 alias entries; traversal `..`, cycles,
unknown forest и targets вне build отвергаются. Link/parent/file identities
проверяются до и после enrichment. Map связывает alias, actual link chain,
canonical regular header и SHA256. Record и normalized deps используют canonical
whitelist ID. Offline replay применяет только проверенный map к retained
whitelist; JSON не разрешает открытие host paths. Legacy observed schema1
не содержит aliases. Existing caps/pins и missing-closure требования сохраняются.

Локальные tests с checkpoint capture03 явно SYNTHETIC: 337 original argv через
injected runner и 11 alias shapes из retained evidence. Они не запускают
compiler, Qt, Cargo или ELF и не создают receipts для failed capture03.
