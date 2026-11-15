# Каталог полных профилей: API P2 для P6

Все результаты ниже — DATA. Сохранение и выбор не разрешают запуск ядра,
сетевые эффекты или обход compiler/capability gate. Активная сессия при
обновлении каталога не меняется. Имена недоверенные, чувствительные и требуют
экранирования в UI; DTO намеренно не реализуют Debug/Serialize.

## Адаптер Desktop

`SubscriptionService::catalog(source: i64, query: ProfileQuery)` возвращает
`Result<CatalogPage, SubscriptionError>`. Repository предоставляет тот же метод
с `RepositoryError`. Страница содержит `catalog_version: 2`, total,
source_generation, snapshot_generation, snapshot_revision и
`profiles: Vec<(CatalogProfile, CatalogSelection)>`.
raw_count/unique_count/duplicate_count относятся к snapshot до фильтрации.
Native roots сохраняют multiplicity и не схлопываются: каждый входит в
raw_count и unique_count; duplicate_count отражает только legacy URI dedup.

`CatalogProfile::Server(ServerProfile)` содержит прежний endpoint summary.
`CatalogProfile::Xray(NativeSummary)` содержит id, source_id, ordinal, name,
favorite, available, requires_reselection. У полного профиля нет host/port.
Числовые IDs server и native принадлежат разным пространствам: ключ UI должен
содержать вид профиля. Нельзя передавать native ID в server-only API.

Хранить рядом с отображённой строкой её непрозрачный `CatalogSelection`.
`SubscriptionService::select_catalog_profile(selection)` и
`EncryptedSubscriptionRepository::resolve_catalog(selection)` возвращают
`ResolvedCatalogProfile { entry: ProfileEntry, source_id, source_generation,
snapshot_generation, snapshot_revision }`. Token связывает source, вид,
fingerprint и все поколения страницы. Устаревший token даёт Conflict,
недоступное избранное — NotFound. Для повторного выбора получить новую страницу.
В current-path одной транзакции original расшифровывается и разбирается один
раз общим composition verifier; resolve использует тот же report.
Fingerprint выбранного ordinal проверяется до выдачи entry.

`set_catalog_favorite(selection, bool)` работает с обоими видами и проверяет
CAS. Для недоступной historical записи false удаляет её; true не делает её
доступной. Суммарный лимит избранного источника — 20 000.

Передать `ProfileEntry::Server` прежнему server compiler, а Xray — native
validator/compiler P3. Не использовать generic server fallback. Конфликт
provider/global settings должен оставаться видимым на следующем этапе.

`approve_local_profiles(name, &ProfileImportReport, cancel, backup)` сохраняет
точный original и проекцию атомарно. Backup нужен при прежнем format4 admission.
`offline_profiles(id, cancel)` читает профильный original без сети. Для
revision-bound выбора использовать resolve, а не offline + старый ordinal.
Старые `profiles`, `resolve_profile`, `approve_local_import`, `offline` остаются
совместимыми server-only API. Native не преобразуется в ServerProfile;
legacy список может содержать только недоступные прежние избранные endpoints.

## Staging и review

Fetch/service использует `Subscription::stage_profiles_cancellable` и
`ProfileStagedUpdate`; `PendingRefresh::report()` теперь возвращает
`&ProfileImportReport`. Потребителям заменить `.servers` на `.entries` с явным
match вида. Summary.accepted считает roots; семь roots дают семь записей.
Native всегда требует review. `approve_after_review` подтверждает хранение
DATA, но не activation. Старый staging API крейта yonik-subscription оставлен
отдельно. `commit_profiles` публикует `profile_snapshot()`, проверяя ticket.
`Subscription::upgrade_staged` позволяет server-only staging перейти к v2
с тем же ticket и повторной DATA-проверкой original. Совместимый
`PendingRefresh<StagedUpdate>::accept_clean` использует этот bridge; сетевой
fetch сразу создаёт `PendingRefresh<ProfileStagedUpdate>`.

Не обновлённые desktop/backend ожидания flattened JSON нужно адаптировать в
P6: JSON root больше не даёт по одной selectable строке на outbound; native
review report содержит entries и не содержит native_json/servers.

## Формат и миграция

Версия проекции — отдельный `profile_projection.version = 2`. SQLite
`user_version` 1/2/3/4/5 сохраняет прежний смысл формата source/routing payload;
P2 не подменяет его номером проекции. Прежние migrations 1→2→3 и format4/5
admission сохранены. Парные native_profiles/profile_projection создаются
транзакционно. При отсутствии актуального marker каталог перестраивается из
encrypted snapshot в IMMEDIATE-транзакции; snapshot до успешного commit
не меняется, сеть не используется.

Legacy profiles и его UNIQUE(source_id,fingerprint) сохраняются без изменения
server HMAC domain или AEAD. Новая native_profiles имеет собственный
AUTOINCREMENT id и не имеет UNIQUE по fingerprint: одинаковые roots — multiset.
profile_projection хранит source, version, generation, revision, native_count.
Native payload — encrypted tuple (2, name, favorite), с отдельным AAD domain
native-xray-projection-v2 и координатами id/source/fingerprint/generation/
revision/ordinal/present. Точные raw roots восстанавливаются из отдельно
зашифрованного original snapshot, не из summary.

Native HMAC domain `yonik-profile-fingerprint\0v2\0xray\0` включает repository
identity и source ID. Объекты канонизируются по декодированным ключам, массивы
сохраняют порядок; исключены только top-level remarks/tag. Строковые escape
формы эквивалентны. Числа сохраняют лексическую форму, включая 1e999, без f64;
1 и 1.0 намеренно могут иметь разные identity. P1 ограничивает root 64 KiB,
общую сумму roots 32 MiB, глубину 64 и количество 20 000 до materialization.
Канонизация работает по одному bounded root, без копии всего Value и без
повторного разбора snapshot для каждого summary.

Однозначные identity сохраняют ID и favorite при rename/reorder. Для
дубликатов сохраняется multiset; если соответствие избранного неоднозначно,
старая запись остаётся unavailable/reselection, новые не наследуют favorite.
Прежний flattened outbound favorite никогда не назначается целому balancer:
он остаётся Server unavailable. Смена семантики даёт новую identity.

Backup/restore сохраняет старые schema/AEAD проверки и дополнительно проверяет
точный DDL парной native-проекции, multiset-схему, counts, source/snapshot
координаты, sequence и каждый native ciphertext, включая historical favorite.
Неизвестные таблицы рядом с v2-проекцией отклоняются.

Незашифрованные marker/count не доказывают полноту набора. Для current catalog,
resolve и backup состав live-строк сверяется с authenticated original snapshot:
точные вид, ordinal и keyed fingerprint, с сохранением multiplicity roots и
прежнего URI dedup. Missing/extra/replaced строки, включая повтор ordinal у
одинаковых roots, дают `RepositoryError::Corrupt`. Источники с одним marker и
нулём оставшихся строк тоже проверяются. Historical favourites проходят AEAD
и остаются недоступными; от них не требуется соответствие текущему original.
Verifier разбирает original один раз на source, работает с bounded P1 report
и hash maps, проверяет отмену между записями. Поиск по snapshot для каждой
строки не выполняется. Отсутствующая старая проекция по-прежнему перестраивается
атомарно; повреждённая current-проекция не принимается за полный каталог.

Format4/5 admission сравнивает presence и все столбцы `native_profiles`
(порядок id) и `profile_projection` (порядок source_id) между live и closed
backup, в рамках общего byte budget. Изменение только ciphertext избранного
после backup даёт Conflict с rollback версии/новой записи; нужен свежий backup.
Существующие cancellation и cleanup/Unknown гарантии admission не меняются.

## Границы проверки

`full_profile_catalog` — temporary repositories/test keys, чистые DATA-тесты.
Существующие profile_selection/subscription_import_failure/
subscription_refresh_contract содержат loopback HTTP tests. Без отдельного
network grant их можно компилировать, но исполнять только явно выбранные pure
тесты. Compile/pure evidence не является Linux/runtime acceptance.
