pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import cloud.highpriority.yonik

ApplicationWindow {
    readonly property var backendForDiagnostics: backend
    id: window

    readonly property bool systemFakeDnsEnabled: state.system_fake_dns_enabled === true
    width: 420
    height: 760
    minimumWidth: 380
    minimumHeight: 600
    visible: true
    title: "yonik · " + (state.build_id || "local")
    objectName: "yonikWindow"
    color: "#100e14"
    palette.window: "#100e14"
    palette.windowText: "#f7f2fc"
    palette.text: "#f7f2fc"
    palette.buttonText: "#f7f2fc"
    palette.highlight: "#c4a5f3"
    palette.base: "#1a1720"
    palette.button: "#1a1720"
    palette.mid: "#36303f"
    palette.alternateBase: "#211b2b"
    palette.light: "#50435e"
    palette.dark: "#100e14"
    palette.placeholderText: "#9ba1ab"
    palette.highlightedText: "#100e14"
    font.family: bodyFont.status === FontLoader.Ready ? bodyFont.name : "Noto Sans"
    font.pixelSize: 14
    FontLoader { id: bodyFont; source: "qrc:/fonts/Onest.ttf" }
    FontLoader { id: displayFont; source: "qrc:/fonts/Unbounded.ttf" }
    readonly property color surface: "#1a1720"
    readonly property color mint: "#85e6bd"
    readonly property color warning: "#ffc480"
    readonly property color selectedSurface: "#2b203b"
    readonly property color line: "#36303f"
    readonly property bool editable: state.ready && !state.busy && !state.system_busy && !state.can_stop && !state.closed
    readonly property string actionText: state.can_stop
        ? (state.status === "CleanupError" ? tr("Повторить остановку", "Retry stopping")
           : (["Preparing", "Starting", "Checking"].indexOf(state.status) >= 0 ? tr("Отменить подключение", "Cancel connection") : tr("Отключить", "Disconnect")))
        : tr("Подключить", "Connect")
    property string language: "ru"
    property int page: 0
    property int settingsOrigin: 0
    property string settingsSection: ""
    property double maintenanceRequestSequence: 0
    property bool reducedMotion: false
    property var desiredProfileKind: null
    property var desiredProfilePage: null
    property var desiredProfileId: null
    property var desiredSourceId: null
    readonly property bool selectionConfirmed: (desiredProfileId === null || state.selected_profile === desiredProfileId && state.selected_kind === desiredProfileKind && state.selected_catalog_page === desiredProfilePage)
        && (desiredSourceId === null || state.source_id === desiredSourceId)
    property bool subscriptionImport: false
    property var subscriptionImportPreviousSource: null
    property bool handledCleanImport: false
    property int importedCount: 0
    property int skippedImportCount: 0
    property string importNotice: ""
    property bool importHasWarnings: false
    property bool localImportActive: false
    property bool localImportObserved: false
    property bool localImportReview: false
    property string commandContext: "connection"
    readonly property string connectionError: state.connection_error || (!state.ready ? state.error || "" : "")
    readonly property string sourceError: state.source_error || ""
    readonly property bool sourceLoading: state.busy && state.refresh_source_id !== undefined && state.refresh_source_id !== null
    function sourceFeedbackText() {
        if (sourceError) return errorText(sourceError)
        if (state.pending) return tr("Импорт ожидает проверки", "Import awaits review")
        if (sourceLoading) return tr("Загрузка подписки…", "Loading subscription…")
        return importNotice
    }
    property bool searchQueued: false
    readonly property var sourceNameCounts: {
        const counts = Object.create(null)
        for (const source of state.sources) counts[source.name] = (counts[source.name] || 0) + 1
        return counts
    }
    function subscriptionName(source) {
        return sourceNameCounts[source.name] > 1
            ? source.name + " · #" + source.id : source.name
    }
    function openAdd(localNetwork = false) {
        addDialog.localNetwork = localNetwork
        addDialog.open()
    }
    function showImportResult(saved, skipped) {
        importHasWarnings = skipped > 0 || saved === 0
        importNotice = saved > 0 ? tr("Профили сохранены: ", "Profiles saved: ") + saved
                                  : tr("Подходящих профилей нет", "No compatible profiles")
        if (skipped > 0) importNotice += tr(" · пропущено: ", " · skipped: ") + skipped
        importNoticeTimer.restart()
    }
    function submitLocalImport(command) {
        desiredSourceId = null
        desiredProfileId = null
        subscriptionImport = false
        searchDelay.stop()
        searchQueued = false
        page = 1
        localImportReview = true
        localImportActive = true
        localImportObserved = false
        send(command)
        configImportDialog.close()
    }
    function selectSource(id) {
        desiredSourceId = id
        desiredProfileId = null
        send({command: "select_source", id: id})
    }
    function selectProfile(id, kind) {
        desiredProfileId = id
        desiredProfileKind = kind
        desiredProfilePage = state.catalog_page
        send({command: "select_catalog", kind: kind, id: id, page: state.catalog_page})
    }
    function openSettings() {
        settingsOrigin = page
        settingsSection = ""
        page = 2
    }
    function back() {
        if (page === 2 && settingsSection !== "") settingsSection = ""
        else if (page === 2) page = settingsOrigin
        else if (page === 1) page = 0
    }
    property string parseError: ""
    property var state: ({ready: false, busy: true, error: null, pending: null,
        sources: [], sources_total: 0, sources_offset: 0, source_id: null, profiles: [], total: 0, offset: 0,
        revision: 0, status: "Disconnected", selected_profile: null,
        probe_custom: false, probe_expected_status: 204, probe_result: null,
        tcp_busy: false, tcp_name: null, tcp_result: null,
        tcp_invalidated: false, network_observed: false,
        network_routes: false, network_resolver: false, network_manager: false,
        selected_name: "", engine: "xray", active_name: "", active_engine: "", port: 10808, can_connect: false, can_stop: false})
    readonly property bool canEditProbe: state.ready && !state.busy && !state.system_busy && !state.can_stop && !state.closed
    readonly property color ink: "#f7f2fc"
    readonly property color muted: "#b5adbf"
    readonly property color accent: "#c4a5f3"

    function tr(ru, en) { return language === "ru" ? ru : en }
    function send(command) {
        const sourceCommands = ["import_text", "import_file", "cancel_local_import", "import_source", "refresh", "cancel_refresh", "rename_source", "delete_source", "set_source_hwid", "select_source", "source_page", "approve_refresh", "discard_refresh", "review_page", "query", "select_profile", "select_catalog", "catalog_favorite"]
        commandContext = sourceCommands.indexOf(command.command) >= 0 ? "source" : "connection"
        if (!state.closed) backend.dispatch(JSON.stringify(command))
    }
    // Общий для всех жизней routing Loader; ID используется только для correlation.
    property double catalogRequestSequence: 0
    function nextCatalogRequestId() {
        if (!Number.isSafeInteger(catalogRequestSequence) || catalogRequestSequence < 0 || catalogRequestSequence >= Number.MAX_SAFE_INTEGER) return 0
        catalogRequestSequence += 1
        return catalogRequestSequence
    }
    property bool routingPending: false
    property double routingRequestId: 0
    property double routingExpectedSavedId: 0
    property var routingFeedback: null
    function completeRouting(ack) {
        if (!routingPending || !ack || ack.request_id !== routingRequestId) return
        if (!ack.error && routingExpectedSavedId && ack.saved_id !== routingExpectedSavedId)
            ack = {request_id: ack.request_id, error: "routing_ack_identity", saved_id: null}
        routingFeedback = ack
        routingPending = false
    }
    function sendRouting(command) {
        if (routingPending || state.closed) return 0
        routingRequestId += 1
        command.request_id = routingRequestId
        if (command.expected_revision === undefined) command.expected_revision = state.routing_revision
        routingExpectedSavedId = command.command === "edit_routing" ? command.rule.id : 0
        routingFeedback = null
        routingPending = true
        commandContext = "routing"
        backend.dispatch(JSON.stringify(command))
        return routingRequestId
    }
    function query(offset) {
        if (!state.ready || state.source_id === null) { searchQueued = false; return }
        if (state.busy || state.pending) { searchQueued = true; return }
        searchQueued = false
        send({command: "query", search: search.text, favorites_only: false, offset: offset})
    }
    property int startupSequence: 0
    property string startupPending: ""
    function saveStartup(capture, autostart, autoconnect) {
        if (startupPending || !state.ready || !state.startup || startupSequence >= 2147483647) return
        startupSequence += 1
        startupPending = String(startupSequence)
        const command = Object.create(null)
        command.command = capture ? "autoconnect_target_set" : "startup_preferences_set"
        command.request_id = startupPending
        command.expected_revision = state.startup.revision
        if (!capture) { command.autostart_into_tray = autostart; command.autoconnect = autoconnect }
        send(command)
    }
    function readSnapshot() {
        try {
            const raw = backend.snapshot_json
            if (!raw || raw.length > 4194304) return
            const next = JSON.parse(raw)
            if (next && Object.keys(next).length === 0) return
            if (next && typeof next.error === "string" && !Array.isArray(next.sources) && !Array.isArray(next.profiles)) {
                if (commandContext === "routing") completeRouting({request_id: routingRequestId, error: next.error, saved_id: null})
                const update = commandContext === "source" ? {error: next.error, source_error: next.error} : {error: next.error, connection_error: next.error}
                if (next.maintenance_ack && typeof next.maintenance_ack === "object") update.maintenance_ack = next.maintenance_ack
                if (next.logs && typeof next.logs === "object" && !Array.isArray(next.logs) && typeof next.logs.request_id === "string") update.logs = next.logs
                if (next.startup) update.startup = next.startup
                if (next.startup && next.startup.request_id === startupPending && next.startup.save !== "pending") startupPending = ""
                state = Object.assign({}, state, update)
                if (commandContext === "source") {
                    subscriptionImport = false
                    if (handledCleanImport) {
                        handledCleanImport = false
                        importedCount = 0
                        if (state.pending) reviewDialog.open()
                    }
                }
                parseError = ""
                return
            }
            if (!next || !Array.isArray(next.sources) || !Array.isArray(next.profiles)) {
                parseError = tr("Не удалось прочитать состояние приложения.", "Could not read application state.")
                return
            }
            if (next.source_id !== state.source_id) {
                search.text = typeof next.search === "string" ? next.search : ""
                searchQueued = false
                searchDelay.stop()
            }
            if (desiredSourceId === next.source_id) desiredSourceId = null
            if (desiredProfileId !== null && desiredProfileId === next.selected_profile
                    && desiredProfileKind === next.selected_kind && desiredProfilePage === next.selected_catalog_page) {
                if (page === 1) page = 0
                desiredProfileId = null
            }
            if (next.language) language = next.language
            state = next
            if (next.startup && next.startup.request_id === startupPending && next.startup.save !== "pending") startupPending = ""
            completeRouting(next.routing_ack)
            if (searchQueued && !next.busy && !next.pending) searchDelay.restart()
            parseError = ""
            if (window.localImportActive && next.busy) window.localImportObserved = true
            if (window.localImportActive && (next.error || (window.localImportObserved && !next.busy))) window.localImportActive = false
            if (window.localImportObserved && !next.busy && !next.pending) window.localImportReview = false
            if (next.source_error) {
                subscriptionImport = false
                handledCleanImport = false
                importedCount = 0
                skippedImportCount = 0
            }
            const newSubscription = subscriptionImport && next.source_id !== null
                && next.source_id !== subscriptionImportPreviousSource
            if (next.pending && !next.busy && !reviewDialog.visible && !handledCleanImport) {
                if (newSubscription) {
                    subscriptionImport = false
                    handledCleanImport = true
                    importedCount = next.pending.accepted
                    skippedImportCount = next.pending.rejected
                    send({command: importedCount > 0 ? "approve_refresh" : "discard_refresh"})
                } else {
                    reviewDialog.open()
                }
            }
            if (!next.pending && !next.busy && !next.source_error) {
                if (handledCleanImport) {
                    handledCleanImport = false
                    showImportResult(importedCount, skippedImportCount)
                    importedCount = 0
                    skippedImportCount = 0
                } else if (newSubscription && next.total > 0) {
                    // Чистый импорт сохраняется ядром без промежуточного отчёта.
                    subscriptionImport = false
                    showImportResult(next.total, 0)
                }
            }
            if (!next.pending && reviewDialog.visible) reviewDialog.close()
        } catch (_) {
            parseError = tr("Не удалось прочитать состояние приложения.", "Could not read application state.")
        }
    }
    function statusText(status) {
        const values = {
            Unknown: ["Состояние сети неизвестно", "Network state unknown"],
            NoManagedPolicy: ["Управляемых правил нет", "No managed policy"],
            TunnelStarting: ["Туннель запускается; доступ не подтверждён", "Tunnel starting; connectivity unverified"],
            VerifiedRules: ["Правила подтверждены; доступ не подтверждён", "Rules verified; connectivity unverified"],
            RecoveryRequired: ["Требуется восстановление сети", "Network recovery required"],
            Disconnected: ["Отключено", "Disconnected"], Preparing: ["Подготовка…", "Preparing…"],
            Starting: ["Запуск ядра…", "Starting engine…"], Checking: ["Проверка доступа…", "Checking connectivity…"],
            Connected: ["Подключено", "Connected"], Stopping: ["Отключение…", "Stopping…"],
            Limited: ["Соединение ограничено", "Connection limited"],
            Error: ["Ошибка подключения", "Connection failed"], CleanupError: ["Не удалось завершить отключение", "Cleanup failed"]
        }
        const pair = values[status]
        return pair ? tr(pair[0], pair[1]) : tr("Состояние недоступно", "State unavailable")
    }
    function probeResultText(result) {
        if (!result) return ""
        const kinds = {
            http: ["Ответ HTTPS", "HTTPS response"],
            tls: ["Ошибка TLS", "TLS error"],
            timeout: ["Истекло время проверки", "Check timed out"],
            transport: ["Ошибка транспорта", "Transport error"]
        }
        const pair = kinds[result.kind]
        return (pair ? tr(pair[0], pair[1]) : tr("Результат проверки", "Check result"))
            + (result.http_status !== null && result.http_status !== undefined ? " · HTTP " + result.http_status : "")
            + (result.elapsed_ms !== null && result.elapsed_ms !== undefined ? " · " + result.elapsed_ms + tr(" мс", " ms") : "")
    }
    function tcpStatusText(status) {
        const values = {
            reachable: ["TCP доступен", "TCP reachable"],
            not_applicable: ["Неприменимо: UDP или неизвестный транспорт", "Not applicable: UDP or unknown transport"],
            resolver_unavailable: ["DNS недоступен: требуется systemd-resolved с Varlink", "DNS unavailable: systemd-resolved with Varlink is required"],
            dns_failed: ["Не удалось разрешить DNS-имя", "DNS resolution failed"],
            connect_failed: ["Не удалось установить TCP-соединение", "TCP connection failed"],
            dns_timeout: ["Истекло время DNS-запроса", "DNS timed out"],
            connect_timeout: ["Истекло время TCP-соединения", "TCP connection timed out"],
            cancelled: ["TCP-проверка отменена", "TCP check cancelled"]
        }
        const pair = values[status]
        return pair ? tr(pair[0], pair[1]) : tr("Результат недоступен", "Result unavailable")
    }
    function tcpTimingText(result) {
        if (!result) return ""
        const dns = result.dns_ms !== null && result.dns_ms !== undefined
            ? "DNS: " + result.dns_ms + tr(" мс", " ms")
            : (["reachable", "connect_failed", "connect_timeout"].indexOf(result.status) >= 0
                ? tr("DNS не потребовался", "DNS not needed") : "DNS: —")
        const tcp = result.connect_ms !== null && result.connect_ms !== undefined
            ? tr("TCP, медиана: ", "TCP median: ") + result.connect_ms + tr(" мс", " ms") : "TCP: —"
        const samples = result.samples_ms ? result.samples_ms.length : 0
        return dns + " · " + tcp + " · " + tr("выборки: ", "samples: ") + samples + "/" + result.samples_requested
    }
    function tcpEndpointText(result) {
        if (!result) return ""
        const host = result.host.indexOf(":") >= 0 ? "[" + result.host + "]" : result.host
        return result.name + " · " + host + ":" + result.port
            + (result.selected_address ? tr(" · адрес: ", " · address: ") + result.selected_address : "")
    }
    function tcpCheckedAtText(result) {
        if (!result) return ""
        if (!result.checked_at_ms) return tr("Время проверки недоступно", "Check time unavailable")
        return tr("Проверено: ", "Checked: ")
            + new Date(result.checked_at_ms).toLocaleString(Qt.locale(language === "ru" ? "ru_RU" : "en_US"))
    }
    function networkObservationText() {
        const available = tr("доступно", "available")
        const unavailable = tr("недоступно", "unavailable")
        return tr("Наблюдение за изменениями: маршруты — ", "Change monitoring: routes — ")
            + (state.network_routes ? available : unavailable)
            + "; DNS — " + (state.network_resolver ? available : unavailable)
            + "; NetworkManager — " + (state.network_manager ? available : unavailable)
    }
    function reviewText(row) {
        const reasons = {
            malformed_uri: ["Некорректная ссылка", "Malformed URI"],
            unsupported_protocol: ["Протокол не поддерживается", "Unsupported protocol"],
            invalid_port: ["Некорректный порт", "Invalid port"],
            invalid_host: ["Некорректный адрес", "Invalid host"],
            invalid_credentials: ["Некорректные учётные данные", "Invalid credentials"],
            invalid_encoding: ["Некорректная кодировка", "Invalid encoding"],
            invalid_json: ["Некорректный JSON", "Invalid JSON"],
            too_large: ["Превышен размер записи", "Record too large"],
            duplicate_parameter: ["Повторяющийся параметр", "Duplicate parameter"],
            conflicting_parameter: ["Конфликт параметров", "Conflicting parameters"],
            unknown_parameter: ["Неизвестный параметр", "Unknown parameter"],
            unsupported_transport: ["Транспорт не поддерживается", "Unsupported transport"],
            unsupported_security: ["Защита не поддерживается", "Unsupported security"],
            unsupported_cipher: ["Шифр не поддерживается", "Unsupported cipher"],
            unsupported_option: ["Опция не поддерживается", "Unsupported option"],
            unsafe_option: ["Небезопасная опция", "Unsafe option"],
            legacy_option: ["Устаревшая опция", "Legacy option"]
        }
        const fields = {
            source: ["источник", "source"], endpoint: ["адрес", "endpoint"],
            credentials: ["учётные данные", "credentials"],
            parameters: ["параметры", "parameters"], payload: ["содержимое", "payload"]
        }
        const reason = reasons[row.code]
        const field = fields[row.field]
        return (row.kind === "rejected" ? tr("Строка ", "Line ") : tr("Принятый профиль ", "Accepted profile "))
            + row.position + ": " + (reason ? tr(reason[0], reason[1]) : tr("Требует проверки", "Review required"))
            + (field ? " (" + tr(field[0], field[1]) + ")" : "")
    }
    function isUnsupportedSelector(reason) {
        return reason === "unsupported_selector"
    }

    function errorText(key) {
        const messages = {
            listen_port_busy: ["Порт занят. Повторите подключение.", "Port is busy. Try connecting again."],
            startup: ["Не удалось запустить приложение.", "Could not start the application."],
            keyring_locked: ["Хранилище секретов заблокировано. Разблокируйте системный кошелёк и повторите запуск.", "Secret storage is locked. Unlock the system wallet and restart."],
            keyring_missing: ["Системное хранилище секретов недоступно.", "System secret storage is unavailable."],
            storage: ["Ошибка локального хранилища. Проверьте доступ к данным приложения.", "Local storage error. Check access to application data."],
            logs_save_failed: ["Не удалось сохранить страницу журнала. Проверьте выбранный путь.", "Could not save the log page. Check the selected path."],
            logs_save_durability_unknown: ["Страница журнала опубликована, но надёжность записи не подтверждена.", "The log page was published, but write durability is unconfirmed."],
            catalog: ["Не удалось прочитать каталог приложений.", "Could not read the application catalog."],
            preferences_write: ["Не удалось сохранить настройки. Изменение не применено. Проверьте preferences.json в каталоге данных.", "Could not save settings. The change was not applied. Check preferences.json in the data directory."],
            invalid_input: ["Проверьте введённые данные и адрес подписки.", "Check the input and subscription URL."],
            invalid_ip: ["Проверьте IP-адрес или домен.", "Check the IP address or domain."],
            busy: ["Дождитесь завершения текущей операции.", "Wait for the current operation to finish."],
            source_in_use: ["Сначала отключите прокси, затем удалите подписку.", "Disconnect the proxy before deleting this subscription."],
            refresh_required: ["Загрузка уже завершилась. Проверьте список серверов.", "Loading has already finished. Check the server list."],
            source_required: ["Сначала выберите подписку.", "Select a subscription first."],
            unsupported_proxy: ["Загрузка подписки через прокси пока не поддерживается. Выберите прямой маршрут.", "Fetching subscriptions through a proxy is not supported yet. Choose Direct."],
            hwid_required: ["Провайдер требует ID устройства. Включите его в настройках подписки.", "The provider requires a device ID. Enable it in subscription settings."],
            hwid_limit: ["Достигнут лимит устройств подписки. Проверьте устройства у провайдера.", "The subscription device limit has been reached. Review devices with your provider."],
            hwid_rejected: ["Провайдер отклонил ID устройства. Обратитесь в поддержку провайдера.", "The provider rejected the device ID. Contact provider support."],
            hwid_redirect: ["Провайдер перенаправляет запрос с ID устройства. Проверьте ссылку подписки.", "The provider redirects device ID requests. Check the subscription link."],
            fetch: ["Не удалось загрузить подписку. Проверьте сеть и адрес. Сохранённые профили не изменены.", "Could not fetch the subscription. Check the network and URL. Saved profiles are unchanged."],
            "import": ["Не удалось распознать профили подписки.", "Could not parse subscription profiles."],
            review_required: ["Сначала подтвердите или отмените текущий импорт.", "Approve or discard the current import first."],
            profile_required: ["Сначала выберите профиль.", "Select a profile first."],
            profile_unavailable: ["Профиль недоступен или список изменился. Выберите профиль заново.", "The profile is unavailable or the list has changed. Select the profile again."],
            engine_missing: ["Прокси-ядро не найдено. Установите выбранное ядро и перезапустите приложение.", "Proxy engine not found. Install the selected engine and restart the application."],
            system_unsupported: ["Системный режим недоступен: helper сообщает system_tun=false.", "System mode unavailable: helper reports system_tun=false."],
            fake_dns_policy: ["Для Fake DNS выберите «Прокси» по умолчанию. Доменные правила должны входить в указанные суффиксы.", "Select Proxy as the default for Fake DNS. Domain rules must be covered by the configured suffixes."],
            system_denied: ["Нет разрешения на системное подключение.", "System connection authorization denied."],
            system_owner_lost: ["Helper перезапущен. Проверьте состояние сети.", "Helper restarted. Check network state."],
            system_timeout: ["Время ожидания helper истекло. Исход неизвестен.", "Helper timed out. Outcome unknown."],
            system_unavailable: ["Helper недоступен. Проверьте состояние сети.", "Helper unavailable. Check network state."],
            engine_config: ["Профиль несовместим с выбранным ядром. Проверьте параметры подключения.", "The profile is incompatible with the selected engine. Check connection settings."],
            engine_failed: ["Прокси-ядро не запущено или завершилось с ошибкой. Проверьте профиль и наличие ядра.", "The proxy engine is not running or exited with an error. Check the profile and engine installation."],
            engine_unavailable: ["Sing-box пока недоступен. Выберите Xray в настройках подключения.", "Sing-box is currently unavailable. Select Xray in connection settings."],
            probe_target_invalid: ["Укажите корректный HTTPS URL (до 2048 символов) и ожидаемый статус 200–299.", "Enter a valid HTTPS URL (up to 2048 characters) and an expected status of 200–299."],
            check_http_status: ["Сайт проверки вернул неожиданный HTTP-статус. Редирект не считается успехом.", "The check endpoint returned an unexpected HTTP status. Redirects are not successful."],
            check_tls: ["Не удалось проверить TLS сайта проверки.", "TLS verification failed for the check endpoint."],
            check_timeout: ["Истекло время проверки доступа через прокси.", "The connectivity check through the proxy timed out."],
            check_transport: ["Не удалось выполнить запрос через прокси: ошибка транспорта.", "The request through the proxy failed with a transport error."],
            check_failed: ["Прокси работает, но доступность интернета не подтверждена.", "The proxy is running, but internet access is unconfirmed."],
            network_changed: ["Обнаружено изменение сети. Прежняя HTTPS-проверка больше не актуальна; прокси-ядро продолжает работать с ограниченным статусом. Переподключитесь для новой HTTPS-проверки.", "A network change was detected. The previous HTTPS check is no longer current; the proxy engine keeps running with limited status. Reconnect for a new HTTPS check."],
            tcp_failed: ["Не удалось выполнить TCP-проверку. Повторите попытку.", "Could not complete the TCP check. Try again."],
            cancelled: ["Операция отменена.", "Operation cancelled."],
            cleanup_failed: ["Не удалось завершить отключение. Повторите остановку перед выходом.", "Cleanup failed. Retry stopping before quitting."]
        }
        const startupMessages = {
            preferences_conflict: ["Настройки изменены другим writer. Показаны актуальные значения; проверьте их и повторите действие явно.", "Settings changed by another writer. Current values are shown; review them and explicitly retry."],
            startup_conflict: ["Настройки изменились. Проверьте актуальные значения и повторите действие.", "Settings changed. Review current values and retry."],
            startup_binding: ["Цель или владелец недоступны. При замене БД или владельца перезапустите приложение; выберите сохранённый профиль и подтвердите цель заново.", "Target or owner unavailable. If the database or owner changed, restart the application; select a saved profile and confirm the target again."],
            startup_timeout: ["Время ожидания startup истекло. Автоподключение не повторяется в этом запуске.", "Startup timed out. Autoconnect will not retry in this run."],
            startup_admission: ["Автоподключение заблокировано текущим состоянием. Автоматического unlock или другого режима нет.", "Autoconnect blocked by current state. No automatic unlock or alternative mode."],
            startup_xdg: ["Настройки сохранены, но применение записи XDG не подтверждено. Чужие файлы сохранены.", "Settings saved, but XDG entry application is unconfirmed. Foreign files are preserved."],
            startup_xdg_unknown: ["Запись XDG опубликована, надёжность записи неизвестна. Автоподключение в этом запуске заблокировано.", "XDG entry published; durability unknown. Autoconnect blocked in this run."]
        }
        const editorMessages = {
            action: ["Недопустимое действие правила маршрутизации.", "Invalid routing rule action."],
            format: ["Некорректный формат черновика маршрутизации.", "Invalid routing draft format."],
            duplicate_parameter: ["Повторяющийся параметр", "Duplicate parameter"],
            unsupported_option: ["Опция не поддерживается", "Unsupported option"],
            routing_stale: ["Черновик изменился. Ввод сохранён в форме; откройте актуальное правило заново или явно создайте новое.", "The draft changed. Input is preserved in the form; reopen the current rule or explicitly create a new one."],
            routing_ack_identity: ["Ответ сохранения не совпал с правилом. Ввод сохранён; проверьте черновик.", "Save response did not match the rule. Input is preserved; check the draft."],
            routing_storage: ["Черновик не сохранён: повреждение или конфликт БД. Исходник сохранён; перезапустите приложение.", "Draft not saved: damaged database or conflict. Original preserved; restart the application."],
            domain: ["Некорректный домен", "Invalid domain"], cidr: ["Некорректный IP/CIDR: проверьте биты сети", "Invalid IP/CIDR: check network bits"],
            executable: ["Нужен абсолютный путь без . и ..", "An absolute path without . and .. is required"],
            broad: ["Подтвердите правило для любого трафика", "Confirm matching all traffic"],
            ports: ["Порты назначения: 1–65535, до 16 непустых диапазонов.", "Destination ports: 1–65535, up to 16 nonempty ranges."],
            ports_overlap: ["Диапазоны портов пересекаются или повторяются.", "Port ranges overlap or repeat."],
            protocols: ["Укажите tcp и/или udp без повторов.", "Enter tcp and/or udp without duplicates."],
            transport_input: ["Проверьте формат протоколов и диапазонов портов.", "Check protocol and port range syntax."],
            id: ["Недопустимый или повторяющийся ID", "Invalid or duplicate ID"],
            limit: ["Лимит: 256 правил, 64 значения в группе, 4096 байт в значении", "Limit: 256 rules, 64 values per group, 4096 bytes per value"]
        }
        const pair = messages[key] || startupMessages[key] || editorMessages[key]
        return pair ? tr(pair[0], pair[1]) : tr("Категория ошибки отсутствует в каталоге сообщений.", "The error category is missing from the message catalog.")
    }

    DesktopBridge {
        id: backend
        onSnapshot_jsonChanged: window.readSnapshot()
    }
    Component.onCompleted: { backend.initialize(); readSnapshot(); backend.dispatch(JSON.stringify({command: "subscription_visibility", visible: window.visible})) }
    onVisibleChanged: backend.dispatch(JSON.stringify({command: "subscription_visibility", visible: window.visible}))
    Shortcut {
        sequence: "Escape"
        enabled: !noticesDialog.visible && !subscriptionOptionsDialog.visible && !addDialog.visible && !configImportDialog.visible && !reviewDialog.visible && !renameDialog.visible && !deleteDialog.visible
        onActivated: window.back()
    }

    component PlainLabel: Label {
        textFormat: Text.PlainText
        color: window.ink
        wrapMode: Text.Wrap
    }
    component SectionTitle: PlainLabel {
        font.pixelSize: 22
        font.family: displayFont.status === FontLoader.Ready ? displayFont.name : window.font.family
        font.weight: Font.DemiBold
    }
    component SmallLabel: PlainLabel {
        color: window.muted
        font.pixelSize: 13
    }


    component ChoiceBox: ComboBox {
        id: choice
        implicitHeight: 42
        leftPadding: 10
        rightPadding: 30
        indicator: PlainLabel {
            x: choice.width - width - 9
            anchors.verticalCenter: parent.verticalCenter
            text: "⌄"
            color: choice.enabled ? window.accent : window.muted
            font.pixelSize: 20
        }
        background: Rectangle {
            implicitWidth: 136
            radius: 10
            color: window.surface
            border.color: choice.activeFocus ? window.accent : window.line
        }
    }

    component ActionButton: Button {
        id: control
        implicitHeight: 44
        leftPadding: 16
        rightPadding: 16
        Accessible.name: text
        function activateFromKeyboard() {
            if (!enabled) return
            if (checkable) toggle()
            clicked()
        }
        Keys.onReturnPressed: event => { if (!event.isAutoRepeat) control.activateFromKeyboard() }
        Keys.onEnterPressed: event => { if (!event.isAutoRepeat) control.activateFromKeyboard() }
        contentItem: PlainLabel {
            text: control.text
            font: control.font
            color: !control.enabled ? window.muted : (control.highlighted ? "#100e14" : window.ink)
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 10
            property color hoverColor: control.down ? "#35283f" : control.hovered ? "#26212b" : window.surface
            color: control.highlighted && control.enabled ? window.accent : hoverColor
            border.width: control.activeFocus ? 2 : 1
            border.color: control.activeFocus ? window.accent : window.line
            opacity: control.enabled ? 1 : 0.55
            Behavior on hoverColor { ColorAnimation { duration: window.reducedMotion ? 0 : 160 } }
            Behavior on opacity { NumberAnimation { duration: window.reducedMotion ? 0 : 120 } }
        }
    }
    component SettingsRow: ActionButton {
        id: row
        property string description: ""
        property string symbol: ""
        property bool network: false
        Layout.fillWidth: true
        implicitHeight: Math.max(55, contentItem.implicitHeight + 14)
        leftPadding: 16; rightPadding: 16
        contentItem: RowLayout {
            spacing: 14
            Rectangle {
                implicitWidth: 36; implicitHeight: 36; radius: 10; color: row.network ? "#252e2c" : "#2a2033"
                PlainLabel { anchors.centerIn: parent; text: row.symbol; color: row.network ? window.mint : window.accent; font.pixelSize: 21 }
            }
            ColumnLayout {
                Layout.fillWidth: true; spacing: 5
                PlainLabel { Layout.fillWidth: true; text: row.text; font.weight: Font.Medium; font.pixelSize: 15 }
                SmallLabel { text: row.description; Layout.fillWidth: true; font.pixelSize: 12 }
            }
            PlainLabel { text: "›"; color: window.muted; font.pixelSize: 24 }
        }
    }
    component HelpButton: ActionButton {
        id: help
        property string explanation: ""
        text: "?"
        implicitWidth: 32
        implicitHeight: 32
        leftPadding: 6
        rightPadding: 6
        Accessible.name: window.tr("Подробнее", "More information")
        Accessible.description: explanation
        ToolTip {
            parent: help
            visible: help.hovered || help.activeFocus || help.down
            delay: 200
            timeout: 15000
            width: Math.min(340, window.width - 80)
            contentItem: PlainLabel { text: help.explanation; font.pixelSize: 13 }
            background: Rectangle { color: "#302638"; border.color: "#675174"; radius: 10 }
        }
    }
    component PanelScroll: ScrollView {
        readonly property bool atStart: contentItem.atYBeginning
        readonly property bool atEnd: contentItem.atYEnd
        readonly property bool moving: contentItem.moving
        clip: true
        contentWidth: availableWidth
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        Component.onCompleted: contentItem.boundsBehavior = Flickable.StopAtBounds
    }
    component MintSwitch: Switch {
        id: control
        Layout.fillWidth: true
        implicitHeight: Math.max(38, contentItem.implicitHeight + 12)
        spacing: 10
        indicator: Rectangle {
            implicitWidth: 38
            implicitHeight: 22
            radius: 11
            x: control.width - width
            y: (control.height - height) / 2
            color: control.checked ? "#18362e" : window.color
            border.color: control.activeFocus ? window.accent : control.checked ? window.mint : window.line
            Rectangle {
                width: 14
                height: 14
                radius: 7
                y: 4
                x: control.checked ? parent.width - width - 4 : 4
                color: control.checked ? window.mint : window.muted
            }
        }
        contentItem: PlainLabel {
            rightPadding: control.indicator.width + control.spacing
            text: control.text
            color: control.enabled ? window.ink : window.muted
            verticalAlignment: Text.AlignVCenter
        }
    }
    component SettingsTabs: RowLayout {
        id: tabs
        required property var pages
        property int currentIndex: 0
        Layout.fillWidth: true
        spacing: 5
        Repeater {
            model: tabs.pages
            delegate: ActionButton {
                required property int index
                required property var modelData
                objectName: modelData.id
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                implicitHeight: 36
                leftPadding: 5
                rightPadding: 5
                text: modelData.label
                highlighted: tabs.currentIndex === index
                Accessible.checkable: true
                Accessible.checked: highlighted
                onClicked: tabs.currentIndex = index
            }
        }
    }
    component SettingsGroup: Rectangle {
        default property alias rows: groupContent.data
        Layout.fillWidth: true
        implicitHeight: groupContent.implicitHeight + 20
        radius: 12
        color: window.surface
        border.color: window.line
        ColumnLayout {
            id: groupContent
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: 10
            spacing: 8
        }
    }
    component Divider: Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: window.line }
    component DarkDialog: Dialog {
        id: dialog
        padding: window.width <= 400 ? 14 : 20
        Overlay.modal: Rectangle { color: "#ab0c0a10" }
        background: Rectangle { color: window.surface; radius: 16; border.color: window.line }
        header: PlainLabel {
            text: dialog.title
            font.pixelSize: 19
            font.weight: Font.DemiBold
            leftPadding: 20; rightPadding: 20; topPadding: 20; bottomPadding: 8
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: window.height < 720 ? 18 : 28
        spacing: window.height < 720 ? 12 : 20
        RowLayout {
            Layout.fillWidth: true
            ActionButton {
                objectName: "homeButton"
                visible: window.page !== 0
                text: "‹"
                implicitWidth: 44
                leftPadding: 8; rightPadding: 8
                font.pixelSize: 22
                Accessible.name: window.tr("Назад", "Back")
                onClicked: window.back()
            }
            RowLayout {
                spacing: 10
                Image {
                    Layout.preferredWidth: 28
                    Layout.preferredHeight: 28
                    source: "qrc:/icons/yonik.svg"
                    sourceSize.width: 56
                    sourceSize.height: 56
                }
                PlainLabel {
                    text: "yonik"; font.pixelSize: 27
                    font.family: displayFont.status === FontLoader.Ready ? displayFont.name : window.font.family
                    font.weight: Font.DemiBold
                }
            }
            Item { Layout.fillWidth: true }
            ActionButton {
                objectName: "settingsButton"
                visible: window.page !== 2
                implicitWidth: 44
                leftPadding: 8; rightPadding: 8
                text: "⚙"
                font.family: "Noto Sans"
                font.pixelSize: 27
                Accessible.name: window.tr("Настройки", "Settings")
                onClicked: window.openSettings()
            }
        }
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: window.page
            PanelScroll {
                id: homeScroll
                ColumnLayout {
                    width: homeScroll.availableWidth
                    height: Math.max(implicitHeight, homeScroll.availableHeight)
                    spacing: 0
                    SmallLabel {
                        visible: window.height >= 720
                        text: window.tr("ПОДКЛЮЧЕНИЕ", "CONNECTION")
                        font.pixelSize: 11; font.letterSpacing: 2
                        Layout.bottomMargin: 12
                    }
                    ActionButton {
                        id: serverCard
                        objectName: "serverPickerButton"
                        Layout.fillWidth: true
                        implicitHeight: window.height < 720 ? 80 : 92
                        leftPadding: 18; rightPadding: 18
                        enabled: window.state.ready && !window.state.closed
                        Accessible.name: window.tr("Выбрать сервер", "Choose server") + ": " + serverName.text
                        onClicked: window.page = 1
                        background: Rectangle {
                            radius: 20
                            border.color: serverCard.activeFocus ? window.accent : serverCard.hovered ? "#755589" : "#493254"
                            border.width: serverCard.activeFocus ? 2 : 1
                            gradient: Gradient {
                                GradientStop { position: 0; color: serverCard.down ? "#352340" : "#2a1b36" }
                                GradientStop { position: 1; color: "#17101f" }
                            }
                            Behavior on border.color { ColorAnimation { duration: window.reducedMotion ? 0 : 160 } }
                        }
                        contentItem: RowLayout {
                            spacing: 14
                            Rectangle {
                                implicitWidth: 44; implicitHeight: 44; radius: 14; color: "#372544"
                                PlainLabel { anchors.centerIn: parent; text: "◎"; color: "#d9c6fc"; font.pixelSize: 28 }
                            }
                            ColumnLayout {
                                Layout.fillWidth: true; spacing: 5
                                SmallLabel { text: window.state.can_stop ? window.tr("Текущий сервер", "Current server") : window.tr("Сервер", "Server"); font.pixelSize: 11 }
                                PlainLabel {
                                    id: serverName
                                    objectName: "mainServerName"
                                    Layout.fillWidth: true
                                    text: (window.state.can_stop ? window.state.active_name : window.state.selected_name) || window.tr("Выберите сервер", "Choose a server")
                                    maximumLineCount: 1; elide: Text.ElideRight; font.weight: Font.Medium; font.pixelSize: 17
                                }
                            }
                            PlainLabel { text: "›"; color: "#d9c6fc"; font.pixelSize: 28 }
                        }
                    }
                    Item { Layout.fillHeight: true; Layout.minimumHeight: 24 }
                    Button {
                        id: powerButton
                        objectName: "mainConnectButton"
                        Layout.alignment: Qt.AlignHCenter
                        implicitWidth: Math.min(window.width - 100, window.height < 720 ? 164 : 224); implicitHeight: implicitWidth
                        scale: down ? 0.96 : hovered && enabled ? 1.025 : 1
                        Behavior on scale { ScaleAnimator { duration: window.reducedMotion ? 0 : 160; easing.type: Easing.OutCubic } }
                        enabled: window.state.ready && !window.state.closed && (window.state.can_stop || (window.state.can_connect && window.selectionConfirmed))
                        Accessible.name: window.actionText
                        text: window.actionText
                        onClicked: window.send({command: window.state.can_stop ? "stop" : "connect"})
                        Keys.onReturnPressed: if (enabled) clicked()
                        Keys.onEnterPressed: if (enabled) clicked()
                        background: Rectangle {
                            radius: width / 2
                            color: "#17101f"
                            border.color: powerButton.activeFocus ? "#d9c6fc" : "#483253"
                            border.width: powerButton.activeFocus ? 3 : 1
                            Rectangle {
                                anchors.fill: parent; anchors.margins: -12
                                radius: width / 2; color: "transparent"; border.color: "#271c30"
                            }
                            Rectangle {
                                anchors.fill: parent; anchors.margins: 12; radius: width / 2
                                gradient: Gradient {
                                    GradientStop { position: 0; color: window.state.can_stop ? "#392746" : "#d9c6fc" }
                                    GradientStop { position: 1; color: window.state.can_stop ? "#1d1427" : "#b69ad9" }
                                }
                                border.color: window.state.can_stop ? "#c4a5f3" : "#e2d3f8"
                                opacity: powerButton.enabled ? (powerButton.down ? 0.8 : 1) : 0.65
                            }
                        }
                        contentItem: Item {
                            Canvas {
                                anchors.centerIn: parent; width: 64; height: 64
                                property color stroke: window.state.can_stop ? window.accent : "#100e14"
                                onStrokeChanged: requestPaint()
                                onVisibleChanged: if (visible) requestPaint()
                                onPaint: {
                                    const ctx = getContext("2d"); ctx.reset(); ctx.strokeStyle = stroke; ctx.lineWidth = 3.5; ctx.lineCap = "round"
                                    ctx.beginPath(); ctx.arc(32, 33, 23, -Math.PI / 2 + 0.6, 3 * Math.PI / 2 - 0.6); ctx.stroke()
                                    ctx.beginPath(); ctx.moveTo(32, 5); ctx.lineTo(32, 31); ctx.stroke()
                                }
                            }
                        }
                    }
                    RowLayout {
                        Layout.alignment: Qt.AlignHCenter; Layout.maximumWidth: homeScroll.availableWidth; Layout.topMargin: window.height < 720 ? 20 : 26; spacing: 9
                        Rectangle {
                            implicitWidth: 7; implicitHeight: 7; radius: 4
                            color: window.state.status === "Connected" ? window.mint : ["Limited", "CleanupError", "Error"].indexOf(window.state.status) >= 0 ? window.warning : window.accent
                        }
                        PlainLabel {
                            objectName: "mainStatusLabel"
                            Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter
                            font.pixelSize: 22; font.weight: Font.Medium
                            text: !window.state.ready ? window.tr("Инициализация…", "Initializing…") : window.statusText(window.state.status)
                            color: ["Limited", "CleanupError", "Error"].indexOf(window.state.status) >= 0 ? window.warning : window.ink
                            Accessible.role: Accessible.StaticText
                        }
                    }
                    SmallLabel {
                        objectName: "mainErrorLabel"
                        maximumLineCount: 3; elide: Text.ElideRight
                        Layout.fillWidth: true; Layout.topMargin: window.height < 720 ? 8 : 10
                        horizontalAlignment: Text.AlignHCenter
                        text: window.parseError || (window.connectionError ? window.errorText(window.connectionError)
                            : window.state.status === "Limited" ? window.tr("Доступ к интернету не подтверждён", "Internet access is unconfirmed")
                            : window.state.status === "CleanupError" ? window.tr("Повторите остановку перед выходом", "Retry stopping before quitting")
                            : window.state.can_stop ? window.actionText
                            : window.state.selected_name ? (window.state.can_connect ? window.tr("Нажмите, чтобы подключиться", "Press to connect") : window.tr("Подключение для этого профиля недоступно", "Connection is unavailable for this profile")) : window.tr("Добавьте подписку и выберите сервер", "Add a subscription and choose a server"))
                    }
                    SmallLabel {
                        objectName: "selectedNextServerLabel"
                        Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter
                        visible: window.state.can_stop && !!window.state.selected_name && window.state.selected_name !== window.state.active_name
                        Layout.topMargin: visible ? 12 : 0
                        text: window.tr("Выбран для следующего подключения: ", "Selected for next connection: ") + window.state.selected_name + window.tr(" · после отключения", " · after disconnecting")
                    }
                    Item { Layout.fillHeight: true; Layout.minimumHeight: 24 }
                }
            }
            PanelScroll {
                id: serversScroll
                ColumnLayout {
                width: serversScroll.availableWidth
                height: Math.max(implicitHeight, serversScroll.availableHeight)
                spacing: 8
                RowLayout {
                    SectionTitle { Layout.fillWidth: true; text: window.tr("Серверы", "Servers") }
                    ActionButton { objectName: "addSourceButton"; highlighted: true; text: window.tr("Добавить", "Add"); leftPadding: 8; rightPadding: 8; enabled: window.state.ready && !window.state.busy && !window.state.pending; onClicked: window.openAdd() }
                }
                RowLayout {
                    ChoiceBox {
                        id: overviewSources
                        objectName: "profileSourceFilter"
                        Layout.fillWidth: true
                        model: window.state.sources; textRole: "name"; valueRole: "id"
                        currentIndex: { for (let i = 0; i < window.state.sources.length; ++i) if (window.state.sources[i].id === window.state.source_id) return i; return -1 }
                        displayText: {
                            const activeSource = window.state.sources.find(source => source.id === window.state.source_id)
                            return activeSource ? window.subscriptionName(activeSource)
                                : window.state.source_name || window.tr("Нет подписок", "No subscriptions")
                        }
                        delegate: ItemDelegate {
                            id: sourceOption
                            required property var modelData
                            required property int index
                            readonly property bool selectedSource: modelData.id === window.state.source_id
                            objectName: "subscriptionChoice_" + modelData.id
                            width: overviewSources.width
                            height: 42
                            highlighted: overviewSources.highlightedIndex === index
                            background: Rectangle {
                                color: sourceOption.selectedSource ? window.selectedSurface
                                    : sourceOption.highlighted || sourceOption.hovered ? "#24202c" : window.surface
                            }
                            contentItem: RowLayout {
                                PlainLabel { Layout.fillWidth: true; text: window.subscriptionName(sourceOption.modelData); maximumLineCount: 1; elide: Text.ElideRight }
                                PlainLabel { visible: sourceOption.selectedSource; text: "✓"; color: window.mint; Accessible.name: window.tr("Выбрана", "Selected") }
                            }
                        }
                        onActivated: window.selectSource(currentValue)
                        enabled: window.state.ready && !window.state.busy && count > 0
                        Accessible.name: window.tr("Подписка", "Subscription")
                    }
                    ActionButton { objectName: "refreshSourceButton"; text: "↻"; Accessible.name: window.tr("Обновить подписку", "Refresh subscription"); enabled: window.state.ready && window.state.source_local === false && window.state.source_id !== null && !window.state.busy && !window.state.pending; onClicked: window.send({command: "refresh"}) }
                    ActionButton { objectName: "sourceOptionsButton"; text: "⋯"; leftPadding: 8; rightPadding: 8; Accessible.name: window.tr("Параметры подписки", "Source options"); enabled: window.state.ready && !window.state.pending; onClicked: subscriptionOptionsDialog.open() }
                }
                SmallLabel { objectName: "localSourceLabel"; visible: window.state.source_local === true; text: window.tr("Локальный источник", "Local source") }
                RowLayout {
                    visible: window.state.sources_total > 64
                    SmallLabel { Layout.fillWidth: true; text: window.tr("Подписки: ", "Subscriptions: ") + (window.state.sources_offset + 1) + "–" + (window.state.sources_offset + window.state.sources.length) + " / " + window.state.sources_total }
                    ActionButton { objectName: "sourcePreviousButton"; text: "‹"; enabled: !window.state.busy && window.state.sources_offset > 0; onClicked: window.send({command: "source_page", offset: Math.max(0, window.state.sources_offset - 64)}) }
                    ActionButton { objectName: "sourceNextButton"; text: "›"; enabled: !window.state.busy && window.state.sources_offset + window.state.sources.length < window.state.sources_total; onClicked: window.send({command: "source_page", offset: window.state.sources_offset + 64}) }
                }
                RowLayout {
                    visible: window.sourceFeedbackText() !== "" || !!window.parseError || (window.state.busy && window.localImportActive)
                    SmallLabel { objectName: "subscriptionFeedback"; Layout.fillWidth: true; maximumLineCount: 3; elide: Text.ElideRight; color: window.sourceError || window.parseError ? window.warning : window.sourceLoading || window.state.pending ? window.muted : window.importHasWarnings ? window.warning : window.mint; text: window.parseError || window.sourceFeedbackText() }
                    ActionButton { objectName: "cancelSourceRefreshButton"; visible: window.sourceLoading; enabled: window.state.busy && window.state.refresh_source_id !== undefined && window.state.refresh_source_id !== null && typeof window.state.refresh_token === "string"; text: window.tr("Отмена", "Cancel"); onClicked: window.send({command: "cancel_refresh", id: window.state.refresh_source_id, token: window.state.refresh_token}) }
                    ActionButton { objectName: "cancelImportButton"; visible: window.state.busy && window.localImportActive; text: window.tr("Отменить импорт", "Cancel import"); onClicked: window.send({command: "cancel_local_import"}) }
                    ActionButton { objectName: "openReviewButton"; visible: !!window.state.pending; text: window.tr("Проверить", "Review"); onClicked: reviewDialog.open() }
                }
                RowLayout {
                    TextField { id: search; objectName: "profileSearch"; background: Rectangle { color: window.surface; radius: 10; border.color: search.activeFocus ? window.accent : window.line } Layout.fillWidth: true; placeholderText: window.tr("Поиск серверов", "Search servers"); maximumLength: 256; selectByMouse: true; enabled: window.state.ready; onTextEdited: { window.searchQueued = true; searchDelay.restart() } onAccepted: { searchDelay.stop(); window.query(0) } Accessible.name: window.tr("Поиск серверов", "Search servers") }
                    ActionButton { objectName: "clearSearchButton"; visible: search.text.length > 0; text: "×"; Accessible.name: window.tr("Сбросить поиск", "Clear search"); enabled: !window.state.busy; onClicked: { search.clear(); searchDelay.stop(); window.query(0) } }
                }
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.fillHeight: window.state.profiles.length === 0
                        Layout.minimumHeight: window.state.profiles.length ? 48 : 172
                        Layout.preferredHeight: window.state.profiles.length
                            ? Math.min(window.state.profiles.length * 51 + 2, Math.max(155, serversScroll.availableHeight - 162))
                            : 172
                        color: "transparent"
                        ListView {
                            id: profileList
                            objectName: "profileList"
                            anchors.fill: parent
                            anchors.margins: 1
                            clip: true
                            model: window.state.profiles
                            reuseItems: true
                            spacing: 5
                            onCountChanged: if (count === 0) positionViewAtBeginning()
                            Connections {
                                target: window
                                function onStateChanged() {
                                    if (profileList.displayedOffset !== window.state.offset
                                            || profileList.displayedSource !== window.state.source_id
                                            || profileList.displayedSearch !== (window.state.search || "")) {
                                        profileList.displayedOffset = window.state.offset
                                        profileList.displayedSource = window.state.source_id
                                        profileList.displayedSearch = window.state.search || ""
                                        profileList.positionViewAtBeginning()
                                    }
                                }
                            }
                            property int displayedOffset: 0
                            property var displayedSource: null
                            property string displayedSearch: ""
                            boundsBehavior: Flickable.StopAtBounds
                            ScrollBar.vertical: ScrollBar {}
                            delegate: ItemDelegate {
                                id: profileRow
                                objectName: (modelData.kind === "xray" ? "nativeProfile_" : "profileSelect_") + modelData.id
                                required property var modelData
                                required property int index
                                width: ListView.view.width
                                height: 46
                                topPadding: 3
                                bottomPadding: 3
                                highlighted: window.state.selected_kind === modelData.kind && window.state.selected_profile === modelData.id
                                background: Rectangle {
                                    color: profileRow.highlighted ? window.selectedSurface : profileRow.hovered ? "#24202c" : window.surface
                                    border.color: profileRow.activeFocus || profileRow.highlighted ? window.accent : window.line
                                    radius: 8
                                    Rectangle { width: 2; height: parent.height / 2; anchors.verticalCenter: parent.verticalCenter; radius: 1; color: window.accent; visible: profileRow.highlighted }
                                }
                                enabled: window.state.ready && !window.state.busy
                                Accessible.name: modelData.name + ", " + (modelData.kind === "xray" ? window.tr("Полный профиль Xray", "Full Xray profile") : modelData.host)
                                onClicked: if (modelData.selectable !== false) window.selectProfile(modelData.id, modelData.kind)
                                Keys.onReturnPressed: if (enabled) clicked()
                                Keys.onEnterPressed: if (enabled) clicked()
                                contentItem: RowLayout {
                                    spacing: 12
                                    PlainLabel {
                                        Layout.fillWidth: true
                                        text: profileRow.modelData.name
                                        elide: Text.ElideRight
                                        maximumLineCount: 1
                                        font.weight: profileRow.highlighted ? Font.DemiBold : Font.Medium
                                        ToolTip.visible: truncated && profileRow.hovered
                                        ToolTip.text: text
                                    }
                                    SmallLabel {
                                        visible: !profileRow.modelData.available
                                        text: window.tr("Недоступен", "Unavailable")
                                        color: window.warning
                                    }
                                    SmallLabel {
                                        visible: profileRow.highlighted
                                        text: "✓"
                                        color: window.mint
                                        Accessible.name: window.tr("Выбран", "Selected")
                                    }
                                    ToolButton {
                                        id: favoriteButton
                                        objectName: "profileFavorite_" + profileRow.modelData.kind + "_" + profileRow.modelData.id
                                        Layout.preferredWidth: 36
                                        Layout.preferredHeight: 36
                                        background: Rectangle {
                                            radius: 8
                                            color: favoriteButton.hovered || favoriteButton.activeFocus ? "#372a45" : "transparent"
                                        }
                                        text: profileRow.modelData.favorite ? "★" : "☆"
                                        font.pixelSize: 19
                                        palette.buttonText: profileRow.modelData.favorite ? window.accent : window.muted
                                        Accessible.name: profileRow.modelData.favorite ? window.tr("Убрать из избранного", "Remove from favorites") : window.tr("В избранное", "Add to favorites")
                                        enabled: window.state.ready && !window.state.busy
                                        onClicked: window.send({command: "catalog_favorite", kind: profileRow.modelData.kind, id: profileRow.modelData.id, page: window.state.catalog_page, value: !profileRow.modelData.favorite})
                                    }

                                }
                            }
                        }
                        ColumnLayout {
                            anchors.centerIn: parent
                            width: Math.min(parent.width - 40, 400)
                            visible: window.state.profiles.length === 0 && !window.state.busy
                            spacing: 10
                            PlainLabel { Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter; text: window.state.sources.length === 0 ? window.tr("Начните с подписки", "Start with a subscription") : window.tr("Профили не найдены", "No profiles found"); font.pixelSize: 20 }
                            SmallLabel { Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter; text: window.state.sources.length === 0 ? window.tr("Добавьте ссылку, проверьте импорт и выберите сервер.", "Add a link, review the import and choose a server.") : window.tr("Обновите подписку или измените условия поиска.", "Refresh the subscription or change the search filters.") }
                            ActionButton { objectName: "emptyProfilesAction"; Layout.alignment: Qt.AlignHCenter; text: window.state.sources.length === 0 ? window.tr("Добавить подписку", "Add subscription") : search.text.length > 0 ? window.tr("Сбросить поиск", "Clear search") : window.tr("Обновить", "Refresh"); enabled: !window.state.busy && !window.state.pending; onClicked: { if (window.state.sources.length === 0) window.openAdd(); else if (search.text.length > 0) { search.clear(); searchDelay.stop(); window.query(0) } else window.send({command: "refresh"}) } }
                        }
                    }
                    RowLayout {
                        visible: window.state.total > 200
                        SmallLabel { text: window.state.total > 0 ? (window.state.offset + 1) + "–" + (window.state.offset + window.state.profiles.length) + " / " + window.state.total : window.tr("Нет профилей", "No profiles"); Layout.fillWidth: true }
                        ActionButton { objectName: "profilePreviousButton"; text: window.tr("Назад", "Previous"); enabled: window.state.offset > 0 && !window.state.busy; onClicked: window.query(Math.max(0, window.state.offset - 200)) }
                        ActionButton { objectName: "profileNextButton"; text: window.tr("Далее", "Next"); enabled: window.state.offset + window.state.profiles.length < window.state.total && !window.state.busy; onClicked: window.query(window.state.offset + 200) }
                    }


                Item { Layout.fillHeight: true; visible: window.state.profiles.length > 0 }

            }
            }
            ColumnLayout {
                spacing: 14
                SectionTitle { visible: window.settingsSection === ""; text: window.tr("Настройки", "Settings") }
                PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; visible: !!window.state.preferences_warning; text: window.tr("Файл настроек повреждён или имеет неизвестный формат. Применены значения по умолчанию; исходник preferences.json сохранён, запись заблокирована.", "Settings are damaged or unsupported. Defaults are active; the original preferences.json is preserved and writes are blocked.") }
                PlainLabel { objectName: "preferencesDurabilityWarning"; Layout.fillWidth: true; wrapMode: Text.Wrap; visible: !!window.state.preferences_durability_warning; color: window.warning; text: window.tr("Настройки применены, файл обновлён. Не удалось подтвердить синхронизацию каталога: сохранность при сбое питания неизвестна. Откат не выполнен.", "Settings were applied and the file was updated. Directory synchronization could not be confirmed: durability after power loss is unknown. No rollback was performed.") }
                ScrollView {
                    id: settingsIndexScroll
                    objectName: "settingsIndexScroll"
                    visible: window.settingsSection === ""
                    Layout.fillWidth: true; Layout.fillHeight: true
                    clip: true
                    ColumnLayout {
                        width: settingsIndexScroll.availableWidth
                        spacing: 5
                        SettingsRow { objectName: "settingsRoutingButton"; text: window.tr("Маршрутизация", "Routing"); description: window.tr("Сохранённые личные правила", "Saved personal rules"); symbol: "⇄"; onClicked: window.settingsSection = "routing" }
                        SettingsRow { objectName: "settingsConnectionButton"; text: window.tr("Подключение", "Connection"); description: window.tr("Ядро и локальный прокси", "Engine and local proxy"); symbol: "◎"; network: true; onClicked: window.settingsSection = "connection" }
                        SettingsRow { objectName: "settingsDiagnosticsButton"; text: window.tr("Диагностика", "Diagnostics"); description: window.tr("Доступность TCP и проверка HTTPS", "TCP reachability and HTTPS check"); symbol: "≋"; network: true; onClicked: window.settingsSection = "diagnostics" }
                        SettingsRow { objectName: "settingsMaintenanceButton"; text: window.tr("Резервная копия", "Backup"); description: window.tr("Зашифрованная копия и восстановление в новый файл", "Encrypted backup and restore to a new file"); symbol: "⇩"; onClicked: window.settingsSection = "maintenance" }
                        SettingsRow { objectName: "settingsScheduleButton"; text: window.tr("Запуск и обновления", "Startup and updates"); description: window.tr("Автозапуск, цель подключения, подписки", "Autostart, connection target, subscriptions"); symbol: "↻"; onClicked: window.settingsSection = "schedule" }
                        SettingsRow { objectName: "settingsAppearanceButton"; text: window.tr("Интерфейс", "Appearance"); description: window.tr("Язык приложения", "Application language"); symbol: "Aa"; onClicked: window.settingsSection = "appearance" }
                        SettingsRow { objectName: "settingsAboutButton"; text: window.tr("О приложении", "About"); description: window.tr("Сборка и поведение окна", "Build and window behavior"); symbol: "i"; onClicked: window.settingsSection = "about" }
                    }
                }
                Loader {
                    id: settingsPanel
                    objectName: "settingsPanel"
                    Layout.fillWidth: true; Layout.fillHeight: true
                    visible: window.settingsSection !== ""
                    active: window.page === 2 && window.settingsSection !== ""
                    sourceComponent: window.settingsSection === "routing" ? routingPanel : window.settingsSection === "diagnostics" ? diagnosticsPanel
                        : window.settingsSection === "maintenance" ? maintenancePanel
                        : window.settingsSection === "schedule" ? schedulePanel
                        : window.settingsSection === "appearance" ? appearancePanel
                        : window.settingsSection === "about" ? aboutPanel : connectionPanel
                    onLoaded: if (item && !window.reducedMotion) panelEntrance.restart()
                    OpacityAnimator { id: panelEntrance; target: settingsPanel; from: 0.6; to: 1; duration: 120 }
                }
            }
        }
    }
    Component {
        id: maintenancePanel
        MaintenanceView {
            nextRequestId: function() { window.maintenanceRequestSequence += 1; return window.maintenanceRequestSequence }
            sendCommand: function(command) { window.send(command) }
            errorText: function(key) { return window.errorText(key) }
            english: window.language === "en"
            available: window.state.maintenance_available === true && window.editable
            revision: window.state.revision || 0
            response: window.state.maintenance_ack || null
        }
    }
    Component {
        id: routingPanel
        ColumnLayout {
            spacing: 10
            SectionTitle { Layout.fillWidth: true; text: window.tr("Маршрутизация", "Routing") }
            SettingsTabs {
                id: routingTabs
                pages: [
                    {id: "routingRulesTab", label: window.tr("Правила", "Rules")},
                    {id: "routingEditorTab", label: window.tr("Редактор", "Editor")},
                    {id: "routingListsTab", label: window.tr("Списки", "Lists")},
                    {id: "routingCheckTab", label: window.tr("Проверка", "Check")}
                ]
                onCurrentIndexChanged: if (routingScroll.contentItem) routingScroll.contentItem.contentY = 0
            }
            PanelScroll {
                id: routingScroll
                Layout.fillWidth: true
                Layout.fillHeight: true
                objectName: "routingScroll"
                ColumnLayout {
                    id: editor
                    Layout.minimumWidth: 0
                    objectName: "routingEditor"
                    enabled: window.state.selected_kind !== "xray" && window.state.ready && !window.state.closed && !window.routingPending
                    property double catalogExpectedId: 0
                    property bool catalogRequestLimit: false
                    readonly property var displayedCatalog: catalogExpectedId > 0 && window.state.routing_catalog && window.state.routing_catalog.request_id === catalogExpectedId ? window.state.routing_catalog : null
                    function invalidateCatalog() { catalogExpectedId = 0 }
                    function requestCatalog(offset) {
                        invalidateCatalog()
                        const id = window.nextCatalogRequestId()
                        catalogRequestLimit = id === 0
                        if (!id) return
                        catalogExpectedId = id
                        window.send({command: "routing_catalog", request_id: id, processes: processCatalog.checked, query: catalogQuery.text, offset: offset})
                    }
                    property var formRevision: window.state.routing_revision
                    property double pendingRequest: 0
                    property string saveError: ""
                    function settle() {
                        const ack = window.routingFeedback
                        if (!pendingRequest || !ack || ack.request_id !== pendingRequest) return
                        pendingRequest = 0
                        saveError = ack.error || ""
                        if (!saveError) {
                            selectedId = ack.saved_id
                            formRevision = window.state.routing_revision
                        }
                    }
                    Connections { target: window; function onRoutingFeedbackChanged() { editor.settle() } }
                    width: routingScroll.availableWidth
                    spacing: 12
                    property bool advanced: false
                    property double selectedId: 0
                    property var transport: undefined
                    property var platformSources: undefined
                    function newRule() {
                        resetPlatformSources()
                        transport = undefined
                        selectedId = 0
                        formRevision = window.state.routing_revision
                        saveError = ""
                        executableInput.clear()
                        domainInput.clear()
                        cidrInput.clear()
                        protocolInput.clear()
                        portInput.clear()
                        actionInput.currentIndex = 0
                        enabledInput.checked = true
                        broadInput.checked = false
                    }
                    function resetPlatformSources() { platformSources = undefined }
                    property int simpleGroup: 0
                    function values(text) { return text.split("\n").map(s => s.trim()).filter(s => s.length > 0) }
                    function load(rule) {
                        transport = rule.transport === undefined ? undefined : JSON.parse(JSON.stringify(rule.transport))
                        protocolInput.text = transport && transport.transport_protocols ? transport.transport_protocols.join(",") : ""
                        portInput.text = transport && transport.destination_ports ? transport.destination_ports.map(p => p[0] === p[1] ? String(p[0]) : p[0] + "-" + p[1]).join(",") : ""
                        platformSources = rule.platform_sources === undefined ? undefined : JSON.parse(JSON.stringify(rule.platform_sources))
                        selectedId = rule.id
                        formRevision = window.state.routing_revision
                        saveError = ""
                        executableInput.text = rule.executables.join("\n")
                        domainInput.text = rule.domains.join("\n")
                        cidrInput.text = rule.destinations.join("\n")
                        actionInput.currentIndex = ["proxy", "direct", "block"].indexOf(rule.action)
                        enabledInput.checked = rule.enabled
                        broadInput.checked = false
                    }
                    function order(id, delta, remove) {
                        let ids = window.state.routing.rules.map(r => r.id)
                        let index = ids.indexOf(id)
                        if (remove) {
                            window.sendRouting({command: "routing_delete", id: id})
                            return
                        }
                        if (index + delta >= 0 && index + delta < ids.length) {
                            let other = ids[index + delta]; ids[index + delta] = id; ids[index] = other
                        }
                        window.sendRouting({command: "routing_order", ids: ids})
                    }
                    ColumnLayout {
                        visible: routingTabs.currentIndex === 0
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        ActionButton { Layout.fillWidth: true; text: window.tr("Новое правило", "New rule"); highlighted: true; onClicked: { editor.newRule(); routingTabs.currentIndex = 1 } }
                        RowLayout {
                            objectName: "routingDefaultRow"
                            PlainLabel { text: window.tr("Остальной трафик", "Other traffic") }
                            ChoiceBox { model: ["Proxy", "Direct", "Block"]; currentIndex: window.state.routing ? ["proxy", "direct", "block"].indexOf(window.state.routing.default_action) : 0; onActivated: window.sendRouting({command: "routing_default", action: ["proxy", "direct", "block"][currentIndex]}) }
                        }
                        Repeater {
                            model: window.state.routing ? window.state.routing.rules : []
                            delegate: ColumnLayout {
                                id: ruleRow
                                required property var modelData
                                Layout.fillWidth: true
                                PlainLabel { Layout.fillWidth: true; text: "#" + ruleRow.modelData.id + " · " + ruleRow.modelData.action + (ruleRow.modelData.enabled ? "" : window.tr(" · выключено", " · disabled")) }
                                SmallLabel { Layout.fillWidth: true; text: (ruleRow.modelData.transport ? window.tr("Транспортное условие (активация недоступна) · ", "Transport condition (activation unavailable) · ") : "") + (ruleRow.modelData.platform_sources && ruleRow.modelData.platform_sources.length ? window.tr("Платформенный селектор неприменим на Linux", "Platform selector is unsupported on Linux") : (ruleRow.modelData.executables.concat(ruleRow.modelData.domains, ruleRow.modelData.destinations).join(" ∧/∨ ") || window.tr("Любой трафик: перекрывает последующие правила", "Any traffic: shadows following rules"))) }
                                RowLayout {
                                    ActionButton { objectName: "routingEdit" + ruleRow.modelData.id; text: window.tr("Изменить", "Edit"); onClicked: { editor.load(ruleRow.modelData); routingTabs.currentIndex = 1 } }
                                    ActionButton { objectName: "routingUp" + ruleRow.modelData.id; text: "↑"; Accessible.name: window.tr("Выше", "Move up"); onClicked: editor.order(ruleRow.modelData.id, -1, false) }
                                    ActionButton { text: "↓"; Accessible.name: window.tr("Ниже", "Move down"); onClicked: editor.order(ruleRow.modelData.id, 1, false) }
                                    ActionButton { text: "×"; Accessible.name: window.tr("Удалить", "Delete"); onClicked: editor.order(ruleRow.modelData.id, 0, true) }
                                }
                                ActionButton { objectName: "routingDuplicate" + ruleRow.modelData.id; text: window.tr("Дублировать", "Duplicate"); onClicked: { editor.load(ruleRow.modelData); editor.selectedId = 0; editor.formRevision = window.state.routing_revision; routingTabs.currentIndex = 1 } }
                                Divider {}
                            }
                        }
                        ActionButton {
                            objectName: "routingApplyButton"
                            text: window.tr("Применить к сети", "Apply to network")
                            enabled: window.state.selected_kind !== "xray" && window.state.ready && !window.state.busy && !window.routingPending && window.state.connection_mode === "system" && (window.systemFakeDnsEnabled || (!(window.state.system_fake_dns || []).length && window.state.engine === "xray" && window.state.system_tun_available)) && !window.state.system_busy && !window.state.can_stop && !window.state.system_recovery_pending && !!window.state.selected_profile && window.state.source_generation !== null
                            onClicked: window.sendRouting({command: "routing_apply", source_generation: window.state.source_generation, snapshot_revision: window.state.revision, selected_profile_id: window.state.selected_profile})
                        }
                        SmallLabel { Layout.fillWidth: true; text: window.tr("Для применения правил системный помощник должен подтвердить доступ. Проверка правил сама по себе не проверяет подключение и привязку приложений.", "The system helper must confirm access before applying rules. Rule validation alone does not verify connectivity or application attribution.") }
                    }
                    ColumnLayout {
                        visible: routingTabs.currentIndex === 1
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        ActionButton { objectName: "routingModeButton"; text: editor.advanced ? window.tr("Простой режим", "Simple mode") : window.tr("Расширенный режим", "Advanced mode"); onClicked: editor.advanced = !editor.advanced }
                        SmallLabel { visible: editor.advanced; Layout.fillWidth: true; text: window.tr("Совпасть должны все группы. Внутри группы достаточно одной строки.", "All groups must match. Within each group, one matching line is enough.") }
                        ChoiceBox { visible: !editor.advanced; model: [window.tr("Программа", "Executable"), window.tr("Домен", "Domain"), "IP / CIDR"]; onActivated: editor.simpleGroup = currentIndex }
                        PlainLabel { objectName: "routingRuleIdentity"; text: editor.selectedId ? window.tr("Редактирование #", "Editing #") + editor.selectedId : window.tr("Новое правило", "New rule") }
                        SmallLabel { visible: editor.advanced || editor.simpleGroup === 0; Layout.fillWidth: true; text: window.tr("Путь к исполняемому файлу", "Path to the executable") }
                        TextArea { visible: editor.advanced || editor.simpleGroup === 0; id: executableInput; objectName: "routingExecutable"; Layout.fillWidth: true; placeholderText: "/usr/bin/browser"; wrapMode: TextEdit.Wrap; selectByMouse: true }
                        ActionButton {
                            id: catalogToggle
                            objectName: "routingCatalogToggle"
                            visible: editor.advanced || editor.simpleGroup === 0
                            checkable: true
                            text: checked ? window.tr("Скрыть каталог программ", "Hide applications")
                                          : window.tr("Выбрать программу…", "Choose an application…")
                        }
                        SettingsGroup {
                            visible: catalogToggle.visible && catalogToggle.checked
                            TextField { id: catalogQuery; objectName: "routingCatalogQuery"; onTextChanged: editor.invalidateCatalog(); Layout.fillWidth: true; placeholderText: window.tr("Поиск программы", "Search applications") }
                            CheckBox { id: processCatalog; objectName: "routingCatalogProcesses"; onCheckedChanged: editor.invalidateCatalog(); text: window.tr("Запущенные процессы", "Running processes") }
                            ActionButton { objectName: "routingCatalogLoad"; text: window.tr("Загрузить каталог", "Load catalog"); onClicked: editor.requestCatalog(0) }
                            SmallLabel { objectName: "routingCatalogLimit"; Layout.fillWidth: true; visible: editor.catalogRequestLimit; text: window.tr("Исчерпан счётчик запросов каталога. Перезапустите приложение.", "Catalog request counter exhausted. Restart the application.") }
                            SmallLabel { Layout.fillWidth: true; text: window.tr("Выберите программу, чтобы подставить её путь. PID нужен только для справки.", "Select an application to insert its path. The PID is shown for reference only.") }
                            SmallLabel { Layout.fillWidth: true; visible: !!editor.displayedCatalog && editor.displayedCatalog.incomplete; text: window.tr("Каталог неполный: достигнут лимит или нет доступа", "Incomplete catalog: limit reached or access denied") }
                            Repeater {
                                objectName: "routingCatalogRows"
                                model: editor.displayedCatalog ? editor.displayedCatalog.items : []
                                delegate: ActionButton {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    text: modelData.name + (modelData.pid ? " · PID " + modelData.pid : "") + (modelData.executable ? " · " + modelData.executable : window.tr(" · не поддерживается: ", " · unsupported: ") + modelData.unsupported)
                                    enabled: !!modelData.executable
                                    onClicked: { executableInput.text = modelData.executable; catalogToggle.checked = false }
                                }
                            }
                            RowLayout {
                                visible: !!editor.displayedCatalog && editor.displayedCatalog.total > 32
                                ActionButton { objectName: "routingCatalogPrevious"; text: window.tr("Назад", "Previous"); enabled: !!editor.displayedCatalog && editor.displayedCatalog.offset > 0; onClicked: editor.requestCatalog(Math.max(0, editor.displayedCatalog.offset - 32)) }
                                ActionButton { objectName: "routingCatalogNext"; text: window.tr("Далее", "Next"); enabled: !!editor.displayedCatalog && editor.displayedCatalog.offset + 32 < editor.displayedCatalog.total; onClicked: editor.requestCatalog(editor.displayedCatalog.offset + 32) }
                            }
                        }
                        SmallLabel { visible: editor.advanced || editor.simpleGroup === 1; text: window.tr("Домен или *.суффикс", "Domain or *.suffix") }
                        TextArea { visible: editor.advanced || editor.simpleGroup === 1; id: domainInput; objectName: "routingDomain"; Layout.fillWidth: true; placeholderText: "example.org"; wrapMode: TextEdit.Wrap; selectByMouse: true }
                        SmallLabel { visible: editor.advanced || editor.simpleGroup === 2; text: window.tr("IP или канонический CIDR", "IP or canonical CIDR") }
                        TextArea { visible: editor.advanced || editor.simpleGroup === 2; id: cidrInput; objectName: "routingCidr"; Layout.fillWidth: true; placeholderText: "192.0.2.0/24"; wrapMode: TextEdit.Wrap; selectByMouse: true }
                        SmallLabel { visible: editor.advanced; Layout.fillWidth: true; text: window.tr("По одному значению на строку. Process name, UID, cgroup и PID не поддерживаются текущей моделью.", "One value per line. Process names, UID, cgroup and PID are unsupported by the current model.") }
                        SettingsGroup {
                            visible: editor.advanced || editor.transport !== undefined
                            SmallLabel { Layout.fillWidth: true; text: window.tr("Транспорт: TCP или UDP. До 16 диапазонов портов назначения (1–65535). Активация пока недоступна.", "Transport: TCP or UDP. Up to 16 destination port ranges (1–65535). Activation is unavailable.") }
                            TextField { id: protocolInput; objectName: "routingProtocols"; Layout.fillWidth: true; maximumLength: 7; placeholderText: "tcp,udp" }
                            TextField { id: portInput; objectName: "routingPorts"; Layout.fillWidth: true; maximumLength: 191; placeholderText: "443,8000-8080" }
                        }
                        ChoiceBox { id: actionInput; model: ["Proxy", "Direct", "Block"] }
                        CheckBox { id: enabledInput; objectName: "routingEnabled"; checked: true; text: window.tr("Правило включено", "Rule enabled") }
                        CheckBox { id: broadInput; text: window.tr("Разрешить для всего трафика", "Confirm matching all traffic") }
                        RowLayout {
                            ActionButton {
                                objectName: "routingSaveRule"
                                text: window.tr("Подтвердить", "Confirm")
                                onClicked: {
                                    const protocols = protocolInput.text.trim()
                                    const ports = portInput.text.trim()
                                    if (protocols.length > 7 || ports.length > 191 || (protocols && !/^(tcp|udp)(,(tcp|udp))?$/.test(protocols)) || (ports && !/^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$/.test(ports))) { editor.saveError = "transport_input"; return }
                                    editor.transport = protocols || ports || editor.transport !== undefined ? {} : undefined
                                    if (protocols) editor.transport.transport_protocols = protocols.split(",")
                                    if (ports) editor.transport.destination_ports = ports.split(",").map(s => { const p = s.split("-").map(Number); return [p[0], p.length === 1 ? p[0] : p[1]] })
                                    const rules = window.state.routing.rules
                                    const id = editor.selectedId || (rules.reduce((n, r) => Math.max(n, r.id), 0) + 1)
                                    editor.saveError = ""
                                    editor.pendingRequest = window.sendRouting({command: "edit_routing", expected_revision: editor.formRevision, create: editor.selectedId === 0, confirm_broad: broadInput.checked, rule: {id: id, transport: editor.transport, platform_sources: editor.platformSources, enabled: enabledInput.checked, executables: editor.values(executableInput.text), domains: editor.values(domainInput.text), destinations: editor.values(cidrInput.text), action: ["proxy", "direct", "block"][actionInput.currentIndex]}})
                                    editor.settle()
                                }
                            }
                            ActionButton { text: window.tr("Как новое", "As new"); onClicked: { editor.resetPlatformSources(); editor.selectedId = 0; editor.formRevision = window.state.routing_revision; editor.saveError = "" } }
                        }
                        PlainLabel { objectName: "routingSaveError"; Layout.fillWidth: true; visible: !!editor.saveError || !!(window.routingFeedback && window.routingFeedback.error); text: window.errorText(editor.saveError || (window.routingFeedback ? window.routingFeedback.error : "")) }
                    }
                    ColumnLayout {
                        visible: routingTabs.currentIndex === 2
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        PresetPanel {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            snapshot: window.state.presets || ({})
                            routing: window.state.routing || ({})
                            routingRevision: window.state.routing_revision
                            language: window.language
                            onCommand: payload => window.send(payload)
                        }
                    }
                    ColumnLayout {
                        visible: routingTabs.currentIndex === 3
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        SmallLabel { objectName: "routingDiagnosticsScope"; Layout.fillWidth: true; text: window.tr("Ограниченная диагностика сохранённой ревизии ", "Limited diagnostics for saved revision ") + window.state.routing_revision + window.tr(". Отсутствие предупреждений не доказывает совместимость. VPN/LAN здесь не настроены.", ". No warnings does not prove compatibility. VPN/LAN are not configured here.") }
                        SmallLabel { objectName: "routingDiagnosticsIncomplete"; Layout.fillWidth: true; visible: !!window.state.routing_diagnostics && window.state.routing_diagnostics.incomplete; text: window.state.routing_diagnostics && window.isUnsupportedSelector(window.state.routing_diagnostics.error) ? window.tr("Правило #", "Rule #") + window.state.routing_diagnostics.rule_id + window.tr(": селектор неприменим на Linux", ": selector is unsupported on Linux") : window.state.routing_diagnostics && window.state.routing_diagnostics.stale ? window.tr("Отчёт устарел: черновик изменился. Требуется актуальный снимок.", "Report is stale: the draft changed. A current snapshot is required.") : window.tr("Анализ неполный: достигнут лимит или вход не поддерживается.", "Analysis is incomplete: a limit was reached or input is unsupported.") }
                        Repeater {
                            model: window.state.routing_diagnostics ? window.state.routing_diagnostics.warnings : []
                            delegate: SmallLabel {
                                required property var modelData
                                Layout.fillWidth: true
                                text: "#" + modelData.rule_id + " ← " + modelData.earlier + (modelData.kind === "shadowed" ? window.tr(" · условия перекрыты старшим правилом", " · conditions shadowed by an earlier rule") : window.tr(" · возможное пересечение; существование потока не доказано", " · possible overlap; existence of a flow is unproven"))
                            }
                        }
                        TextField { id: explainTarget; objectName: "routingExplainTarget"; Layout.fillWidth: true; placeholderText: window.tr("IP или домен", "IP or domain"); maximumLength: 253 }
                        ActionButton { objectName: "routingExplainButton"; text: window.tr("Проверить правило", "Explain saved draft"); onClicked: window.sendRouting({command: "routing_explain", target: explainTarget.text}) }
                        PlainLabel {
                            objectName: "routingExplanation"
                            Layout.fillWidth: true
                            property var explanation: window.state.routing_explanation
                            visible: !!explanation && explanation.revision === window.state.routing_revision && explanation.request_id === window.routingRequestId
                            text: !explanation ? "" : explanation.result.status === "fixture" ? window.tr("Предварительный расчёт: ", "Preliminary evaluation: ") + explanation.result.action + " · " + explanation.result.origin : window.tr("Неизвестно: ", "Unknown: ") + (explanation.result.reason === "application_witness_missing" ? window.tr("нет подтверждённой атрибуции приложения", "no verified application attribution") : (explanation.result.reason === "dns_witness_missing" || explanation.result.reason === "dns_missing") ? window.tr("нет подтверждённых DNS-данных", "no verified DNS evidence") : window.isUnsupportedSelector(explanation.result.reason) ? window.tr("неприменимый селектор правила #", "unsupported selector in rule #") + explanation.result.rule_id : explanation.result.reason === "evaluation_rejected" ? window.tr("вход отклонён вычислителем", "input rejected by evaluator") : window.tr("причина недоступна", "reason unavailable")) + window.tr(". Это не проверка применения.", ". This does not verify application of routing.")
                        }
                        // Конец блока проверки маршрутов.
                    }
                }
            }
        }
    }

    Component {
        id: connectionPanel
        PanelScroll {
            id: connectionScroll
            ColumnLayout {
                width: connectionScroll.availableWidth; spacing: 10
                PlainLabel { text: window.tr("Подключение", "Connection"); font.pixelSize: 21; font.weight: Font.DemiBold }
                SettingsGroup {
                    RowLayout {
                        Layout.fillWidth: true
                        PlainLabel { Layout.fillWidth: true; text: window.tr("Режим", "Mode") }
                        ChoiceBox {
                            objectName: "connectionModeChoice"
                            Layout.preferredWidth: 210
                            Layout.maximumWidth: connectionScroll.availableWidth * 0.68
                            Accessible.name: window.tr("Режим подключения", "Connection mode")
                            model: [window.tr("Локальный SOCKS5", "Local SOCKS5"), window.tr("Системное подключение", "System connection")]
                            currentIndex: window.state.connection_mode === "system" ? 1 : 0
                            enabled: window.state.selected_kind !== "xray" && window.editable && !window.state.can_unlock
                            onActivated: window.send({command: "set_connection_mode", mode: currentIndex === 1 ? "system" : "local"})
                        }
                        HelpButton { explanation: window.tr("В локальном режиме укажите адрес SOCKS5 в нужном приложении. Для системного подключения нужен системный помощник и разрешение на изменение сети.", "Set the SOCKS5 address in the application you want to use. System mode requires the system helper and permission to change network settings.") }
                    }
                    Divider {}
                    RowLayout {
                        Layout.fillWidth: true
                        PlainLabel { Layout.fillWidth: true; text: window.tr("Ядро", "Engine") }
                        PlainLabel { visible: window.state.selected_kind === "xray"; text: "Xray · Full Xray" }
                        ChoiceBox { visible: window.state.selected_kind !== "xray"; objectName: "engineChoice"; model: window.systemFakeDnsEnabled ? ["xray", "sing-box"] : ["xray"]; currentIndex: window.state.engine === "xray" ? 0 : (window.systemFakeDnsEnabled ? 1 : -1); enabled: window.state.selected_kind !== "xray" && window.editable; onActivated: window.send({command: "set_engine", engine: currentText}); Accessible.name: window.tr("Прокси-ядро", "Proxy engine") }
                        HelpButton { explanation: window.tr("Обрабатывает подключение к серверу. Меняется после отключения и действует до закрытия приложения.", "Handles the server connection. Change after disconnecting; applies until the app exits.") }
                    }
                    PlainLabel { visible: window.state.selected_kind !== "xray" && window.state.engine === "sing-box" && !window.systemFakeDnsEnabled; Layout.fillWidth: true; wrapMode: Text.Wrap; text: window.tr("Sing-box доступен для системного подключения с Fake DNS.", "Sing-box is available for system connections with Fake DNS.") }
                    PlainLabel { visible: window.state.selected_kind === "xray"; Layout.fillWidth: true; text: window.tr("Для полного профиля Xray параметры доступны только для просмотра.", "Settings for full Xray profiles are read-only.") }
                }
                SmallLabel { text: window.tr("Локальный прокси", "Local proxy"); color: window.mint; Layout.topMargin: 4 }
                SettingsGroup {
                    RowLayout {
                        Layout.fillWidth: true
                        TextField { id: proxyAddress; objectName: "proxyAddress"; Layout.fillWidth: true; Layout.minimumWidth: 80; readOnly: true; selectByMouse: true; text: window.state.listen_address || "127.0.0.1:" + window.state.port; Accessible.name: window.tr("Адрес локального прокси", "Local proxy address") }
                        ActionButton { objectName: "proxyCopyButton"; text: window.tr("Копировать", "Copy"); enabled: window.state.ready; onClicked: { proxyAddress.selectAll(); proxyAddress.copy(); proxyAddress.deselect() } }
                        HelpButton { explanation: window.tr("Свободный порт выбирается автоматически при подключении. Здесь показан текущий адрес.", "An available port is chosen automatically when connecting. The current address is shown here.") }
                    }
                }
                ActionButton {
                    id: dnsDetails
                    objectName: "proxyDnsDetailsButton"
                    text: window.tr("DNS для обновлений подписок", "DNS for subscription updates")
                    checkable: true
                    highlighted: checked
                    Layout.fillWidth: true
                }
                SettingsGroup {
                    visible: dnsDetails.checked
                    SmallLabel { Layout.fillWidth: true; text: window.tr("IP:порт или [IPv6]:порт сервера DNS-over-TCP. Используется только для обновлений через прокси. Пустое поле отключает DNS для этих обновлений.", "IP:port or [IPv6]:port of a DNS-over-TCP server. Used only for updates through the proxy. Leave empty to disable DNS for these updates.") }
                    RowLayout {
                        Layout.fillWidth: true
                        TextField { id: proxyFetchDns; objectName: "proxyFetchDns"; Layout.fillWidth: true; maximumLength: 128; text: window.state.proxy_fetch_dns || ""; enabled: window.state.selected_kind !== "xray" && window.editable && !window.state.can_stop; Accessible.name: window.tr("DNS для обновлений через прокси", "Proxy update DNS") }
                        ActionButton { objectName: "saveProxyFetchDns"; text: window.tr("Сохранить", "Save"); enabled: window.state.selected_kind !== "xray" && window.editable && !window.state.can_stop; onClicked: window.send({command: "set_proxy_fetch_dns", upstream: proxyFetchDns.text}) }
                    }
                }
                SettingsGroup {
                    visible: window.state.connection_mode === "system" && window.state.selected_kind !== "xray"
                    SmallLabel {
                        Layout.fillWidth: true
                        text: window.tr("Разделяйте суффиксы запятыми. Пустое поле отключает Fake DNS. Для восстановленных имён доступны доменные правила Proxy и Block.", "Separate suffixes with commas. Leave the field empty to turn Fake DNS off. Proxy and Block domain rules can match recovered names.")
                    }
                    SmallLabel {
                        visible: (window.state.system_fake_dns || []).length > 0 && !window.systemFakeDnsEnabled
                        Layout.fillWidth: true
                        text: window.tr("Выберите «Прокси» по умолчанию. Для доменных правил Fake DNS используйте Proxy и Block внутри указанных суффиксов. Проверьте, что в этой политике нет CIDR и правил по приложениям.", "Select Proxy as the default. Use Proxy and Block domain rules within the configured Fake DNS suffixes. Check that this policy has no CIDR or per-app rules.")
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        enabled: window.editable && !window.state.can_stop && !window.state.system_busy && !window.state.system_recovery_pending
                        TextField {
                            id: systemFakeDns
                            objectName: "systemFakeDns"
                            Layout.fillWidth: true
                            maximumLength: 1024
                            text: (window.state.system_fake_dns || []).join(", ")
                            Accessible.name: window.tr("Доменные суффиксы Fake DNS", "Fake DNS domain suffixes")
                        }
                        ActionButton {
                            objectName: "saveSystemFakeDns"
                            text: window.tr("Сохранить", "Save")
                            onClicked: window.send({command: "set_system_fake_dns", suffixes: systemFakeDns.text})
                        }
                    }
                }
                SmallLabel {
                    visible: window.state.connection_mode === "system"
                    text: window.tr("Системный помощник", "System helper")
                    color: window.mint
                    Layout.topMargin: 4
                }
                SettingsGroup {
                    visible: window.state.connection_mode === "system"
                    SmallLabel {
                        Layout.fillWidth: true
                        text: window.statusText(window.state.system_state || "Unknown")
                    }
                    ActionButton { objectName: "systemStateButton"; enabled: !window.state.system_busy; text: window.tr("Проверить состояние", "Check state"); onClicked: window.send({command: "system_state"}) }
                    ActionButton { objectName: "systemUnlockButton"; enabled: !!window.state.can_unlock && !window.state.system_busy && !window.state.can_stop; visible: !!window.state.can_unlock; Layout.fillWidth: true; text: window.tr("Снять блокировку сети", "Unlock network protection"); onClicked: window.send({command: "system_unlock"}) }
                }
                PlainLabel { Layout.fillWidth: true; visible: !!window.connectionError; color: window.warning; text: window.connectionError ? window.errorText(window.connectionError) : "" }
            }
        }
    }
    Component {
        id: schedulePanel
        ColumnLayout {
            spacing: 10
            PlainLabel { text: window.tr("Запуск и обновления", "Startup and updates"); font.pixelSize: 19; font.weight: Font.DemiBold }
            SettingsTabs {
                id: scheduleTabs
                pages: [
                    {id: "startupTab", label: window.tr("Запуск", "Startup")},
                    {id: "updatesTab", label: window.tr("Подписки", "Subscriptions")}
                ]
                onCurrentIndexChanged: if (startupScroll.contentItem) startupScroll.contentItem.contentY = 0
            }
            PanelScroll {
                id: startupScroll
                Layout.fillWidth: true
                Layout.fillHeight: true
                ColumnLayout {
                    width: startupScroll.availableWidth
                    spacing: 10
                    SettingsGroup {
                        visible: scheduleTabs.currentIndex === 0
                        MintSwitch {
                            objectName: "autostartIntoTray"
                            enabled: window.state.ready && !window.startupPending && !window.state.preferences_warning
                            text: window.tr("Автозапуск в трей при входе", "Start in tray at login")
                            checked: !!window.state.startup && window.state.startup.autostart_into_tray
                            onClicked: window.saveStartup(false, checked, window.state.startup.autoconnect)
                        }
                        MintSwitch {
                            objectName: "startupAutoconnect"
                            enabled: window.state.ready && !window.startupPending && !window.state.preferences_warning
                            text: window.tr("Автоподключение при запуске", "Connect at startup")
                            checked: !!window.state.startup && window.state.startup.autoconnect
                            onClicked: window.saveStartup(false, window.state.startup.autostart_into_tray, checked)
                        }
                        PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; text: window.state.startup && window.state.startup.target ? window.tr("Цель: ", "Target: ") + window.state.startup.target : window.tr("Цель не подтверждена", "No confirmed target") }
                        PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; text: window.tr("Выбрано: ", "Selected: ") + (window.state.selected_name || "—") + " · " + (window.state.engine || "—") + " · " + (window.state.connection_mode || "—") }
                        ActionButton {
                            objectName: "confirmStartupTarget"
                            text: window.tr("Подтвердить текущую цель", "Confirm current target")
                            enabled: window.state.selected_kind !== "xray" && window.state.ready && !!window.state.selected_profile && !window.state.ephemeral && !window.startupPending && !window.state.preferences_warning
                            onClicked: window.saveStartup(true, false, false)
                        }
                        PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; text: window.tr("Подтвердите сервер и параметры для следующих запусков. Приложение подключится при запуске, если включено автоподключение.", "Confirm the server and settings for future launches. The app connects at startup when autoconnect is enabled.") }
                        PlainLabel {
                            Layout.fillWidth: true; wrapMode: Text.Wrap; color: window.warning
                            text: window.startupPending ? window.tr("Сохранение…", "Saving…") : window.state.startup && window.state.startup.xdg === "error" ? window.errorText("startup_xdg") : window.state.startup && window.state.startup.error ? window.errorText(window.state.startup.error) : window.state.startup && (window.state.startup.save === "durability_unknown" || window.state.startup.xdg === "durability_unknown") ? window.tr("Файл опубликован, надёжность записи неизвестна. Автоматические действия не выполняются.", "File published; durability unknown. No automatic actions performed.") : window.state.startup && window.state.startup.attempt === "blocked" ? window.tr("Автоподключение заблокировано до следующего запуска.", "Autoconnect blocked until the next launch.") : window.state.startup && window.state.startup.save === "durable" ? window.tr("Настройки сохранены", "Settings saved") : ""
                        }
                    }
                    SettingsGroup {
                        visible: scheduleTabs.currentIndex === 1
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        PlainLabel { text: window.tr("Обновления подписок", "Subscription updates"); font.pixelSize: 19; font.weight: Font.DemiBold }
                        PlainLabel { text: window.tr("Интервал в часах (не менее 24)", "Interval in hours (at least 24)") }
                        SpinBox {
                            id: scheduleHours
                            objectName: "subscriptionInterval"
                            enabled: window.state.source_local === false
                            from: 24; to: 1193046
                            value: Math.ceil((window.state.subscription_interval_seconds || 86400) / 3600)
                            editable: true
                            onValueModified: window.send({command: "set_subscription_schedule", interval_seconds: value * 3600, background: window.state.subscription_background === true})
                            Accessible.name: window.tr("Интервал обновлений в часах", "Update interval in hours")
                        }
                        MintSwitch {
                            objectName: "subscriptionBackground"
                            enabled: window.state.source_local === false
                            text: window.tr("Разрешить обновления в фоне", "Allow background updates")
                            checked: window.state.subscription_background === true
                            onClicked: window.send({command: "set_subscription_schedule", interval_seconds: window.state.subscription_interval_seconds || 86400, background: checked})
                        }
                        PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; text: window.tr("Общее фоновое окно — 60 секунд. В неизвестной или лимитной сети и при экономии энергии обновления отложены. Отчёт обновления требует подтверждения.", "The shared background window is 60 seconds. Updates are deferred on unknown or metered networks and in power saving mode. The update report requires confirmation.") }
                        PlainLabel { Layout.fillWidth: true; wrapMode: Text.Wrap; visible: window.connectionError === "preferences_write"; color: window.warning; text: visible ? window.errorText(window.connectionError) : "" }
                    }
                }
            }
        }
    }

    Component {
        id: appearancePanel
        ColumnLayout {
            spacing: 18
            PlainLabel { text: window.tr("Интерфейс", "Appearance"); font.pixelSize: 19; font.weight: Font.DemiBold }
            SettingsGroup {
                RowLayout {
                PlainLabel { Layout.fillWidth: true; text: window.tr("Язык", "Language") }
                ChoiceBox { objectName: "languageChoice"; model: ["Русский", "English"]; currentIndex: window.state.language === "en" ? 1 : 0; onActivated: window.send({command: "set_language", language: currentIndex === 0 ? "ru" : "en"}); Accessible.name: window.tr("Язык интерфейса", "Interface language") }
                HelpButton { explanation: window.tr("Язык меняется сразу и сохраняется для следующих запусков.", "The language changes immediately and is remembered for future launches.") }
            }
            }
            PlainLabel { objectName: "appearanceSaveError"; Layout.fillWidth: true; wrapMode: Text.Wrap; visible: window.connectionError === "preferences_write"; color: window.warning; text: visible ? window.errorText(window.connectionError) : "" }
            Item { Layout.fillHeight: true }
        }
    }
    Component {
        id: aboutPanel
        PanelScroll {
            id: aboutScroll
            ColumnLayout {
                width: aboutScroll.availableWidth
                spacing: 18
                SectionTitle { text: "yonik" }
                SmallLabel { text: window.tr("Открытый исходный код", "Open source") }
                Rectangle {
                    Layout.fillWidth: true; implicitHeight: buildDetails.implicitHeight + 32
                    color: window.surface; radius: 16
                    ColumnLayout {
                        id: buildDetails
                        anchors.fill: parent; anchors.margins: 16; spacing: 8
                        SmallLabel { text: window.tr("СБОРКА", "BUILD"); font.pixelSize: 11; font.letterSpacing: 2 }
                        PlainLabel { objectName: "buildIdLabel"; Layout.fillWidth: true; text: window.state.build_id || window.tr("Локальная сборка", "Local build"); font.pixelSize: 13; wrapMode: Text.WrapAnywhere }
                    }
                }
                RowLayout {
                    PlainLabel { Layout.fillWidth: true; text: window.tr("Закрытие и трей", "Window and tray") }
                    HelpButton { explanation: window.tr("С доступным треем закрытие скрывает окно; выход — в меню трея. Без трея окно остаётся открытым для управления.", "With a tray, closing hides the window; quit from the tray menu. Without a tray, the window stays open for control.") }
                }
                ActionButton { objectName: "openNoticesButton"; Layout.fillWidth: true; text: window.tr("Лицензии компонентов", "Component licenses"); onClicked: noticesDialog.open() }
                ActionButton { text: window.tr("Перечитать состояние", "Reload state"); enabled: window.state.ready && !window.state.busy; onClicked: window.send({command: "reload"}) }
                Item { Layout.fillHeight: true }
            }
        }
    }
    Component {
        id: diagnosticsPanel
        ColumnLayout {
            spacing: 10
            SectionTitle { Layout.fillWidth: true; text: window.tr("Диагностика", "Diagnostics") }
            SettingsTabs {
                id: diagnosticsTabs
                pages: [
                    {id: "diagnosticsTcpTab", label: window.tr("TCP", "TCP")},
                    {id: "diagnosticsHttpsTab", label: window.tr("HTTPS", "HTTPS")},
                    {id: "diagnosticsLogsTab", label: window.tr("Журнал", "Logs")}
                ]
                onCurrentIndexChanged: if (diagnosticsScroll.contentItem) diagnosticsScroll.contentItem.contentY = 0
            }
            PanelScroll {
                id: diagnosticsScroll
                Layout.fillWidth: true
                Layout.fillHeight: true
                objectName: "diagnosticsScroll"
                ColumnLayout {
                    width: diagnosticsScroll.availableWidth; spacing: 14
                    ColumnLayout {
                        visible: diagnosticsTabs.currentIndex === 0
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        PlainLabel { Layout.fillWidth: true; visible: !!window.connectionError || !!window.parseError; color: window.warning; text: window.parseError || (window.connectionError ? window.errorText(window.connectionError) : "") }
                            Rectangle {
                                Layout.fillWidth: true
                                implicitHeight: tcpLayout.implicitHeight + 24
                                color: "#1a1720"
                                border.color: "#36303f"
                                radius: 6
                                ColumnLayout {
                                    id: tcpLayout
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    spacing: 5
                                    RowLayout {
                                        Layout.fillWidth: true
                                        PlainLabel {
                                            Layout.fillWidth: true
                                            text: "TCP"
                                            font.weight: Font.DemiBold
                                        }
                                        HelpButton { explanation: window.tr("Три прямые TCP-пробы через обычную сеть. Не проверяет HTTPS, авторизацию или скорость. DNS и TCP вместе — до 5 секунд. После смены сети повторите проверку.", "Three direct TCP samples over the regular network. Does not check HTTPS, authentication or throughput. DNS and TCP together take up to 5 seconds. Rerun after network changes.") + "\n" + window.networkObservationText() }
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        ActionButton {
                                            objectName: "tcpCheckButton"
                                            text: window.tr("Проверить TCP", "Check TCP")
                                            enabled: window.state.selected_kind !== "xray" && window.state.ready && window.state.selected_profile !== null && !window.state.busy && !window.state.tcp_busy
                                            onClicked: window.send({command: "check_tcp"})
                                        }
                                        ActionButton {
                                            objectName: "tcpCancelButton"
                                            visible: !!window.state.tcp_busy
                                            text: window.tr("Отменить", "Cancel")
                                            enabled: !!window.state.tcp_busy
                                            onClicked: window.send({command: "cancel_tcp"})
                                        }
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        ActionButton {
                                            objectName: "batchCheckButton"
                                            text: window.tr("Проверить источник", "Check source")
                                            enabled: window.state.ready && window.state.source_id !== null && !window.state.busy && !(window.state.batch && window.state.batch.busy)
                                            onClicked: window.send({command: "check_batch"})
                                        }
                                        ActionButton {
                                            objectName: "batchCancelButton"
                                            text: window.tr("Отменить серию", "Cancel batch")
                                            visible: !!window.state.batch && window.state.batch.busy
                                            onClicked: window.send({command: "cancel_batch"})
                                        }
                                    }
                                    SmallLabel {
                                        objectName: "batchProgress"
                                        Layout.fillWidth: true
                                        text: window.state.batch ? (window.state.batch.invalidated ? window.tr("Результаты устарели", "Results invalidated") : window.state.batch.completed + " / " + window.state.batch.total + (window.state.batch.cancelled ? window.tr(" · отменено", " · cancelled") : "")) : ""
                                    }
                                    Repeater {
                                        model: window.state.batch ? window.state.batch.rows : []
                                        delegate: SmallLabel {
                                            required property var modelData
                                            Layout.fillWidth: true
                                            text: modelData.name + " · " + modelData.host + ":" + modelData.port + " · " + window.tcpStatusText(modelData.status) + (modelData.connect_ms !== null ? " · " + modelData.connect_ms + " ms" : "")
                                            wrapMode: Text.Wrap
                                        }
                                    }
                                    RowLayout {
                                        visible: !!window.state.batch && window.state.batch.completed > 32
                                        ActionButton {
                                            text: "←"
                                            enabled: window.state.batch && window.state.batch.offset > 0
                                            onClicked: window.send({command: "batch_page", offset: Math.max(0, window.state.batch.offset - 32)})
                                        }
                                        ActionButton {
                                            text: "→"
                                            enabled: window.state.batch && window.state.batch.offset + 32 < window.state.batch.completed
                                            onClicked: window.send({command: "batch_page", offset: window.state.batch.offset + 32})
                                        }
                                    }
                                    SmallLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_busy
                                        text: window.tr("Проверяется: ", "Checking: ") + (window.state.tcp_name || "")
                                        maximumLineCount: 2
                                        elide: Text.ElideRight
                                    }
                                    PlainLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_result
                                        text: window.state.tcp_result ? window.tcpStatusText(window.state.tcp_result.status) : ""
                                        font.weight: Font.Medium
                                    }
                                    SmallLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_result
                                        text: window.tcpEndpointText(window.state.tcp_result)
                                        maximumLineCount: 2
                                        elide: Text.ElideRight
                                    }
                                    SmallLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_result
                                        text: window.tcpTimingText(window.state.tcp_result)
                                    }
                                    SmallLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_result
                                        text: window.tcpCheckedAtText(window.state.tcp_result)
                                    }
                                    PlainLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_invalidated
                                        text: window.tr("Обнаружено изменение сети: TCP-проверка отменена, прежний результат сброшен. Запустите проверку заново вручную.", "A network change was detected: the TCP check was cancelled and the previous result cleared. Run a new check manually.")
                                    }
                                    SmallLabel {
                                        Layout.fillWidth: true
                                        visible: !!window.state.tcp_result && !window.state.tcp_result.network_observed
                                        text: window.tr("Во время TCP-проверки наблюдение за изменениями сети было неполным. Её результат относится к моменту проверки.", "Network change monitoring was incomplete during the TCP check. Its result applies to the time of the check.")
                                    }

                                }
                            }
                    }
                    ColumnLayout {
                        visible: diagnosticsTabs.currentIndex === 1
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                                RowLayout {
                                    PlainLabel { Layout.fillWidth: true; text: window.tr("Проверка HTTPS", "HTTPS check"); font.pixelSize: 18; font.weight: Font.DemiBold }
                                    HelpButton { explanation: window.tr("Проверяет HTTPS через локальный прокси при подключении. TLS проверяется, редиректы не принимаются. Меняется после отключения и применяется со следующего подключения. URL очищается после отправки.", "Checks HTTPS through the local proxy when connecting. TLS is verified; redirects are rejected. Change after disconnecting; applies to the next connection. The URL is cleared after sending.") }
                                }
                                SmallLabel {
                                    Layout.fillWidth: true
                                    text: (window.state.probe_custom ? window.tr("Применена своя проверка", "Custom check applied") : window.tr("Стандартная проверка: gstatic", "Default check: gstatic"))
                                        + window.tr(" · ожидается HTTP ", " · expected HTTP ") + window.state.probe_expected_status
                                        + (window.state.probe_persistent === false ? window.tr(" · URL с параметрами действует до выхода", " · URL with parameters applies until exit") : "")
                                }
                                SmallLabel {
                                    objectName: "probeResultLabel"
                                    Layout.fillWidth: true
                                    visible: window.state.can_stop && !!window.state.probe_result
                                    text: window.state.probe_result ? window.tr("Проверка активной сессии: ", "Active session check: ") + window.probeResultText(window.state.probe_result) : ""
                                }
                                SmallLabel {
                                    objectName: "probeNetworkWarning"
                                    Layout.fillWidth: true
                                    visible: window.state.can_stop && !!window.state.probe_result && !window.state.probe_result.network_observed
                                    text: window.tr("Во время HTTPS-проверки наблюдение за изменениями сети было неполным. Её результат относится к моменту проверки.", "Network change monitoring was incomplete during the HTTPS check. Its result applies to the time of the check.")
                                }
                                PlainLabel { text: window.tr("HTTPS URL новой проверки", "New check HTTPS URL") }
                                RowLayout {
                                    Layout.fillWidth: true
                                    TextField {
                                        id: probeUrl
                                        objectName: "probeUrlInput"
                                        Layout.fillWidth: true
                                        maximumLength: 2048
                                        placeholderText: "https://www.gstatic.com/generate_204"
                                        echoMode: revealProbe.checked ? TextInput.Normal : TextInput.Password
                                        selectByMouse: true
                                        enabled: window.canEditProbe
                                        inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
                                        Accessible.name: window.tr("Секретный HTTPS URL проверки", "Secret check HTTPS URL")
                                    }
                                    CheckBox { id: revealProbe; objectName: "revealProbeUrl"; text: window.tr("Показать", "Show"); enabled: window.canEditProbe }
                                }
                                RowLayout {
                                    PlainLabel { Layout.fillWidth: true; text: window.tr("Ожидаемый HTTP-статус", "Expected HTTP status") }
                                    SpinBox {
                                        id: probeExpectedStatus
                                        objectName: "probeExpectedStatus"
                                        from: 200
                                        to: 299
                                        value: window.state.probe_expected_status || 204
                                        enabled: window.canEditProbe
                                        Accessible.name: window.tr("Ожидаемый HTTP-статус проверки", "Expected check HTTP status")
                                    }
                                }
                                RowLayout {
                                    ActionButton {
                                        objectName: "applyProbeTargetButton"
                                        text: window.tr("Применить", "Apply")
                                        enabled: window.canEditProbe && probeUrl.text.trim().length > 0
                                        onClicked: {
                                            window.send({command: "set_probe_target", url: probeUrl.text.trim(), expected_status: probeExpectedStatus.value})
                                            probeUrl.clear()
                                            revealProbe.checked = false
                                        }
                                    }
                                    ActionButton {
                                        objectName: "resetProbeTargetButton"
                                        text: window.tr("Сбросить проверку", "Reset check")
                                        enabled: window.canEditProbe
                                        onClicked: {
                                            window.send({command: "reset_probe_target"})
                                            probeUrl.clear()
                                            revealProbe.checked = false
                                            probeExpectedStatus.value = 204
                                        }
                                    }
                                }
                    }
                    ColumnLayout {
                        visible: diagnosticsTabs.currentIndex === 2
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        spacing: 8
                        LogsView { Layout.fillWidth: true; backend: window.backendForDiagnostics; english: window.state.language === "en"; response: window.state.logs || null }
                        DiagnosticsExport { Layout.fillWidth: true; backend: window.backendForDiagnostics; english: window.state.language === "en" }
                    }
                    Item { Layout.preferredHeight: 12 }
                }
            }
        }
    }

    Timer { id: importNoticeTimer; interval: 4500; onTriggered: window.importNotice = "" }
    Timer { id: searchDelay; interval: 200; repeat: false; onTriggered: { if (!window.state.busy) window.query(0) } }
    DarkDialog {
        id: noticesDialog
        anchors.centerIn: parent
        width: Math.min(window.width - 28, 570)
        height: Math.min(window.height - 48, 620)
        title: window.tr("Лицензии компонентов", "Component licenses")
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        contentItem: NoticesView { english: window.language === "en" }
    }
    DarkDialog {
        id: subscriptionOptionsDialog
        objectName: "subscriptionOptionsDialog"
        width: Math.min(window.width - 28, 420)
        anchors.centerIn: parent
        modal: true
        title: window.state.source_id === null ? window.tr("Импорт", "Import") : window.tr("Параметры подписки", "Subscription settings")
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        contentItem: ColumnLayout {
            spacing: 8
            SmallLabel {
                visible: window.state.source_id !== null
                Layout.fillWidth: true
                text: overviewSources.displayText
                color: window.mint
            }
            SettingsGroup {
                visible: window.state.source_id !== null
                RowLayout {
                    Layout.fillWidth: true
                    MintSwitch {
                        objectName: "subscriptionHwidChoice"
                        Layout.fillWidth: true
                        text: window.tr("Отправлять ID устройства", "Send device ID")
                        checked: window.state.source_hwid_enabled === true
                        enabled: window.state.ready && window.state.source_local === false && !window.state.busy && !window.state.pending
                        onToggled: {
                            subscriptionOptionsDialog.close()
                            window.send({command: "set_source_hwid", enabled: checked})
                        }
                    }
                    HelpButton { explanation: window.tr("Передаёт провайдеру случайный постоянный ID. Данные устройства не передаются.", "Sends a random persistent ID. Hardware details are not sent.") }
                }
                Divider {}
                ActionButton {
                    objectName: "renameSourceButton"
                    Layout.fillWidth: true
                    text: window.tr("Переименовать", "Rename")
                    enabled: !window.state.busy && !window.state.pending
                    onClicked: {
                        renameInput.text = window.state.source_name || overviewSources.currentText
                        renameDialog.sourceId = window.state.source_id
                        renameDialog.open()
                    }
                }
                ActionButton {
                    objectName: "deleteSourceButton"
                    Layout.fillWidth: true
                    text: window.tr("Удалить подписку", "Delete subscription")
                    enabled: !window.state.busy && !window.state.pending
                    onClicked: {
                        deleteDialog.sourceId = window.state.source_id
                        deleteDialog.sourceName = window.state.source_name || overviewSources.currentText
                        deleteDialog.open()
                    }
                }
            }
            SmallLabel { visible: window.state.source_id !== null; text: window.tr("Импорт", "Import") }
            ActionButton { objectName: "configImportAction"; Layout.fillWidth: true; text: window.tr("Импорт конфигурации", "Import configuration"); enabled: window.editable; onClicked: { subscriptionOptionsDialog.close(); configImportDialog.open() } }
            ActionButton { objectName: "manualEntryButton"; Layout.fillWidth: true; text: window.tr("Добавить сервер вручную", "Add a server manually"); enabled: window.editable; onClicked: { subscriptionOptionsDialog.close(); manualEntry.open() } }
            ActionButton { objectName: "localSubscriptionAction"; Layout.fillWidth: true; text: window.tr("Подписка из локальной сети", "Local-network subscription"); enabled: !window.state.busy; onClicked: { subscriptionOptionsDialog.close(); window.openAdd(true) } }
            ActionButton { objectName: "closeSourceOptionsButton"; Layout.alignment: Qt.AlignRight; text: window.tr("Готово", "Done"); onClicked: subscriptionOptionsDialog.close() }
        }
    }
    DarkDialog {
        id: renameDialog
        objectName: "renameSourceDialog"
        property var sourceId: null
        modal: true; anchors.centerIn: parent; width: Math.min(window.width - 32, 440)
        title: window.tr("Название подписки", "Subscription name")
        closePolicy: Popup.CloseOnEscape
        onClosed: renameInput.clear()
        contentItem: ColumnLayout {
            TextField { id: renameInput; objectName: "renameSourceInput"; Layout.fillWidth: true; maximumLength: 128; selectByMouse: true; Accessible.name: window.tr("Название подписки", "Subscription name") }
            RowLayout {
                ActionButton { objectName: "renameSourceCancelButton"; text: window.tr("Отмена", "Cancel"); onClicked: renameDialog.close() }
                ActionButton { objectName: "renameSourceConfirmButton"; text: window.tr("Сохранить", "Save"); enabled: renameInput.text.trim().length > 0 && !window.state.busy; onClicked: { window.send({command: "rename_source", id: renameDialog.sourceId, name: renameInput.text.trim()}); renameDialog.close() } }
            }
        }
    }
    DarkDialog {
        id: deleteDialog
        objectName: "deleteSourceDialog"
        property var sourceId: null
        property string sourceName: ""
        modal: true; anchors.centerIn: parent; width: Math.min(window.width - 32, 440)
        title: window.tr("Удалить подписку?", "Delete subscription?")
        closePolicy: Popup.CloseOnEscape
        contentItem: ColumnLayout {
            PlainLabel { Layout.fillWidth: true; text: deleteDialog.sourceName; font.bold: true }
            SmallLabel { Layout.fillWidth: true; text: window.tr("Подписка и её серверы будут удалены с этого устройства. Для повторного добавления понадобится ссылка.", "This subscription and its servers will be removed from this device. You will need its link to add it again.") }
            RowLayout {
                ActionButton { objectName: "deleteSourceCancelButton"; text: window.tr("Отмена", "Cancel"); onClicked: deleteDialog.close() }
                ActionButton { objectName: "deleteSourceConfirmButton"; text: window.tr("Удалить", "Delete"); enabled: !window.state.busy; onClicked: { window.desiredProfileId = null; window.desiredSourceId = null; window.send({command: "delete_source", id: deleteDialog.sourceId}); deleteDialog.close(); subscriptionOptionsDialog.close() } }
            }
        }
    }
    DarkDialog {
        id: addDialog
        objectName: "addSourceDialog"
        anchors.centerIn: parent
        width: Math.min(window.width - 32, 470)
        modal: true
        property bool localNetwork: false
        title: localNetwork ? window.tr("Подписка из локальной сети", "Local-network subscription")
                            : window.tr("Добавить подписку", "Add subscription")
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        onClosed: {
            sourceName.clear()
            sourceUrl.clear()
        }
        onOpened: sourceName.forceActiveFocus()

        contentItem: PanelScroll {
            id: addScroll
            implicitHeight: Math.min(addContent.implicitHeight, window.height - 125)
            ColumnLayout {
                id: addContent
                width: addScroll.availableWidth
                spacing: 8

                PlainLabel {
                    text: window.tr("Название", "Name")
                    font.weight: Font.DemiBold
                }
                TextField {
                    id: sourceName
                    objectName: "sourceNameInput"
                    Layout.fillWidth: true
                    implicitHeight: 42
                    maximumLength: 128
                    placeholderText: window.tr("Необязательно", "Optional")
                    selectByMouse: true
                    Accessible.name: window.tr("Название подписки (необязательно)", "Subscription name (optional)")
                    background: Rectangle { color: window.color; radius: 10; border.color: sourceName.activeFocus ? window.accent : window.line }
                    onAccepted: sourceUrl.forceActiveFocus()
                }
                PlainLabel {
                    Layout.topMargin: 4
                    text: window.tr("Ссылка подписки", "Subscription URL")
                    font.weight: Font.DemiBold
                }
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 46
                    radius: 10
                    color: window.color
                    border.color: sourceUrl.activeFocus ? window.accent : window.line
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 4
                        spacing: 4
                        TextField {
                            id: sourceUrl
                            objectName: "sourceUrlInput"
                            Layout.fillWidth: true
                            maximumLength: 8192
                            placeholderText: "https://…"
                            selectByMouse: true
                            inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
                            Accessible.name: window.tr("Ссылка подписки", "Subscription URL")
                            background: Item {}
                            onAccepted: if (sourceAddConfirm.enabled) sourceAddConfirm.clicked()
                        }
                        ActionButton {
                            objectName: "pasteSourceButton"
                            text: window.tr("Вставить", "Paste")
                            implicitHeight: 34
                            leftPadding: 9
                            rightPadding: 9
                            enabled: sourceUrl.canPaste
                            onClicked: {
                                sourceUrl.selectAll()
                                sourceUrl.paste()
                                sourceUrl.forceActiveFocus()
                                sourceUrl.cursorPosition = 0
                            }
                        }
                    }
                }
                Divider { Layout.topMargin: 4 }
                Flow {
                    Layout.fillWidth: true
                    layoutDirection: Qt.RightToLeft
                    spacing: 8
                    ActionButton {
                        id: sourceAddConfirm
                        objectName: "sourceAddConfirmButton"
                        text: window.tr("Импортировать", "Import")
                        highlighted: true
                        enabled: window.state.ready && sourceUrl.text.trim().length > 0 && !window.state.busy && !window.state.pending
                        onClicked: {
                            window.localImportReview = false
                            window.desiredSourceId = null
                            window.desiredProfileId = null
                            window.importNotice = ""
                            window.subscriptionImportPreviousSource = window.state.source_id
                            window.subscriptionImport = true
                            searchDelay.stop()
                            window.searchQueued = false
                            window.page = 1
                            window.send({command: "import_source", name: sourceName.text.trim() || window.tr("Подписка", "Subscription"), url: sourceUrl.text.trim(), local_exception: addDialog.localNetwork, hwid_enabled: false, route: "direct"})
                            sourceUrl.clear()
                            addDialog.close()
                        }
                    }
                }
            }
        }
    }
    DarkDialog {
        id: configImportDialog
        objectName: "configurationImportDialog"
        title: window.tr("Импорт конфигурации", "Import configuration")
        anchors.centerIn: parent
        width: Math.min(window.width - 32, 470)
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        onClosed: { localImportText.clear(); localImportLimit.visible = false }
        contentItem: ColumnLayout {
            spacing: 10
            TextArea {
                id: localImportText
                objectName: "localImportTextInput"
                Layout.fillWidth: true
                Layout.preferredHeight: 116
                placeholderText: window.tr("Вставьте текст конфигурации", "Paste configuration text")
                wrapMode: TextEdit.Wrap
                selectByMouse: true
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
                Accessible.name: window.tr("Текст конфигурации", "Configuration text")
                onTextChanged: if (length > 1048576) { clear(); localImportLimit.visible = true }
            }
            SmallLabel {
                id: localImportLimit
                Layout.fillWidth: true
                visible: false
                color: window.warning
                text: window.tr("Текст слишком длинный. Выберите файл размером до 8 МиБ.", "Text too long. Choose a file up to 8 MiB.")
            }
            Flow {
                Layout.fillWidth: true
                spacing: 8
                ActionButton {
                    objectName: "importTextButton"
                    text: window.tr("Импортировать текст", "Import text")
                    highlighted: true
                    enabled: window.editable && !window.state.pending && localImportText.length > 0
                    onClicked: window.submitLocalImport({command: "import_text", name: window.tr("Локальный импорт", "Local import"), text: localImportText.text})
                }
                ActionButton { objectName: "importFileButton"; text: window.tr("Выбрать файл…", "Choose file…"); enabled: window.editable && !window.state.pending; onClicked: localImportFile.open() }
            }
        }
    }
    ManualEntry {
        id: manualEntry
        english: window.language === "en"
        onSubmitted: function(name, text) { window.submitLocalImport({command: "import_text", name: name, text: text}) }
    }
    FileDialog {
        id: localImportFile; objectName: "localImportFileDialog"
        fileMode: FileDialog.OpenFile
        options: FileDialog.DontResolveSymlinks
        title: window.tr("Импорт конфигурации до 8 MiB", "Import configuration up to 8 MiB")
        onAccepted: {
            const url = selectedFile.toString()
            if (!url.startsWith("file:///")) return
            window.submitLocalImport({command: "import_file", name: window.tr("Локальный импорт", "Local import"), path: decodeURIComponent(url.substring(7))})
        }
    }
    FileDialog {
        id: localBackupFile; objectName: "localImportBackupDialog"
        fileMode: FileDialog.SaveFile
        title: window.tr("Резервная копия в новом файле приватного каталога", "Backup in a new file in a private directory")
        onAccepted: {
            const url = selectedFile.toString()
            if (!url.startsWith("file:///")) return
            window.maintenanceRequestSequence += 1
            window.send({command: "maintenance_start", request_id: window.maintenanceRequestSequence, operation: "backup", destination: decodeURIComponent(url.substring(7)), revision: window.state.revision || 0})
        }
    }
    DarkDialog {
        id: reviewDialog
        objectName: "refreshReviewDialog"
        anchors.centerIn: parent
        width: Math.min(window.width - 32, 520)
        title: window.tr("Проверка импорта", "Review import")
        modal: true
        closePolicy: Popup.CloseOnEscape
        onRejected: window.send({command: "discard_refresh"})
        contentItem: PanelScroll {
            id: reviewScroll
            implicitHeight: Math.min(reviewContent.implicitHeight, window.height - 140)
            ColumnLayout {
            id: reviewContent
            width: reviewScroll.availableWidth
            spacing: 12
            PlainLabel { Layout.fillWidth: true; visible: window.localImportReview; text: window.tr("Перед первым сохранением создайте зашифрованную резервную копию. Исходник сохраняется зашифрованным без изменений.", "Create an encrypted backup before the first save. The original input is stored encrypted without changes.") }
            ActionButton { objectName: "localImportBackupButton"; visible: window.localImportReview; enabled: !window.state.busy && window.state.ready; text: window.tr("Создать резервную копию…", "Create backup…"); onClicked: localBackupFile.open() }
            ActionButton { objectName: "localImportBackupCancelButton"; visible: window.localImportReview && window.state.busy && !!window.state.maintenance_ack; enabled: !!window.state.maintenance_ack && window.state.maintenance_ack.phase !== "cancelling"; text: window.tr("Отменить резервную копию", "Cancel backup"); onClicked: window.send({command: "maintenance_cancel", request_id: window.state.maintenance_ack.request_id}) }
            PlainLabel { objectName: "localImportBackupFeedback"; Layout.fillWidth: true; visible: window.localImportReview && !!window.state.maintenance_ack; text: !window.state.maintenance_ack ? "" : window.state.maintenance_ack.phase === "complete" ? window.tr("Резервная копия готова. Можно сохранить профили.", "Backup ready. You can save profiles.") : window.state.maintenance_ack.error ? window.errorText(window.state.maintenance_ack.error) : window.tr("Подготовка резервной копии…", "Preparing backup…") }
            PlainLabel { Layout.fillWidth: true; visible: window.localImportReview && !!window.sourceError; color: window.warning; text: window.sourceError ? window.errorText(window.sourceError) : "" }
            SmallLabel { Layout.fillWidth: true; text: window.tr("Проверьте, какие профили будут сохранены.", "Review which profiles will be saved.") }
            SettingsGroup {
                PlainLabel { objectName: "importAcceptedCount"; color: window.mint; text: window.tr("Готово к сохранению: ", "Ready to save: ") + (window.state.pending ? window.state.pending.accepted : 0) }
                PlainLabel { objectName: "importRejectedCount"; visible: !!window.state.pending && window.state.pending.rejected > 0; color: window.warning; text: window.tr("Пропущено: ", "Skipped: ") + (window.state.pending ? window.state.pending.rejected : 0) }
                PlainLabel { visible: !!window.state.pending && window.state.pending.flagged > 0; color: window.warning; text: window.tr("Требуют внимания: ", "Flagged: ") + (window.state.pending ? window.state.pending.flagged : 0) }
            }
            PlainLabel { objectName: "nativeJsonWarning"; Layout.fillWidth: true; color: window.warning; visible: !!window.state.pending && !!window.state.pending.native_json; text: window.tr("Подписка содержит конфигурации Xray в JSON. Сохраняйте их только из доверенного источника.", "This subscription contains Xray JSON configurations. Save them only if you trust the source.") }
            ListView {
                id: reviewRows
                Layout.fillWidth: true
                Layout.preferredHeight: visible ? Math.min(150, Math.max(42, contentHeight)) : 0
                visible: !!window.state.pending && window.state.pending.rows_total > 0
                clip: true
                spacing: 8
                model: window.state.pending ? window.state.pending.rows : []
                delegate: PlainLabel {
                    required property var modelData
                    width: reviewRows.width - 20
                    text: window.reviewText(modelData)
                }
                ScrollBar.vertical: ScrollBar { }
            }
            RowLayout {
                visible: !!window.state.pending && window.state.pending.rows_total > 100
                ActionButton {
                    text: window.tr("Назад", "Previous")
                    enabled: !!window.state.pending && window.state.pending.rows_offset > 0 && !window.state.busy
                    onClicked: { reviewRows.positionViewAtBeginning(); window.send({command: "review_page", offset: Math.max(0, window.state.pending.rows_offset - 100)}) }
                }
                SmallLabel { text: window.state.pending ? (window.state.pending.rows_offset + 1) + "–" + Math.min(window.state.pending.rows_offset + 100, window.state.pending.rows_total) + " / " + window.state.pending.rows_total : "" }
                ActionButton {
                    text: window.tr("Далее", "Next")
                    enabled: !!window.state.pending && window.state.pending.rows_offset + 100 < window.state.pending.rows_total && !window.state.busy
                    onClicked: { reviewRows.positionViewAtBeginning(); window.send({command: "review_page", offset: window.state.pending.rows_offset + 100}) }
                }
            }
            Flow {
                Layout.fillWidth: true
                spacing: 8
                layoutDirection: Qt.RightToLeft
                ActionButton { objectName: "approveRefreshButton"; text: window.tr("Сохранить профили", "Save profiles"); highlighted: true; enabled: !!window.state.pending && (window.state.pending.accepted > 0 || window.state.pending.native_json) && !window.state.busy; onClicked: window.send({command: "approve_refresh"}) }
                ActionButton { objectName: "reviewStopButton"; visible: window.state.can_stop; text: window.tr("Отключить", "Disconnect"); onClicked: window.send({command: "stop"}) }
                ActionButton { objectName: "discardRefreshButton"; text: window.tr("Отмена", "Cancel"); enabled: !window.state.busy; onClicked: window.send({command: "discard_refresh"}) }
            }
        }
        }
    }
}
