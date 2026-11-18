pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: panel
    objectName: "presetPanel"
    required property var snapshot
    required property string language
    required property var routing
    required property var routingRevision
    property double request: Date.now() * 1024
    property double pendingRequest: 0
    property string feedback: ""
    readonly property bool builtinSelected: !!(routing.ru_direct && snapshot.builtin
        && routing.ru_direct.snapshot === snapshot.builtin.snapshot)
    onSnapshotChanged: {
        if (snapshot.ack && snapshot.ack.request_id === pendingRequest) {
            feedback = snapshot.ack.error || tr("Готово", "Done")
            pendingRequest = 0
        }
    }
    function feedbackText(key) {
        return ({"Application witness required": tr("Нет данных о приложении для решения", "Application witness missing"), "DNS witness required": tr("Для решения нужны реальные DNS-данные", "Real DNS witness required"), "Evaluation rejected": tr("Ввод отклонён evaluator", "Evaluator rejected input"), busy: tr("Задание или хранилище занято", "Job or storage busy"), storage: tr("Хранилище недоступно", "Storage unavailable"), integrity: tr("Нарушена целостность snapshot", "Snapshot integrity failure"), fetch: tr("Не удалось загрузить списки выбранным путём", "Could not fetch lists over the selected route"), cancelled: tr("Отменено", "Cancelled"), invalid_ip: tr("Введите корректный IP-адрес или домен", "Enter a valid IP address or domain"), invalid_input: tr("Проверьте поля источника", "Check source fields"), engine_config: tr("Политика не прошла проверку ядра", "Engine policy validation failed"), engine_missing: tr("Доверенное ядро недоступно", "Trusted engine unavailable"), profile_required: tr("Выберите профиль для проверки", "Select a profile to validate"), routing_stale: tr("Черновик изменился, повторите действие", "Draft changed, retry the operation"), durability_unknown: tr("Snapshot опубликован, долговечность записи не подтверждена", "Snapshot published, durability unconfirmed")})[key] || key
    }
    function nextRequest() { request += 1; pendingRequest = request; feedback = ""; return request }
    signal command(var payload)
    spacing: 10
    function tr(ru, en) { return language === "ru" ? ru : en }
    CheckBox {
        objectName: "presetBuiltinActivate"
        text: panel.tr("Российские сервисы напрямую", "Russian services direct")
        checked: panel.builtinSelected && panel.routing.ru_direct.enabled
        enabled: !panel.snapshot.busy && panel.pendingRequest === 0 && panel.routingRevision !== null
        nextCheckState: function() { return checkState }
        onClicked: panel.command({command: "preset_activate", builtin: true, enabled: !checked,
            expected_revision: panel.routingRevision, request_id: panel.nextRequest()})
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: !!panel.snapshot.builtin
        text: panel.tr("Local · домены и IP-подсети из kyoresuas/ru-direct · ", "Local · domains and IP subnets from kyoresuas/ru-direct · ")
            + (panel.snapshot.builtin ? panel.snapshot.builtin.date : "")
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: panel.snapshot.current ? panel.tr("Текущая версия: ", "Current version: ") + panel.snapshot.current.version + " · " + new Date(panel.snapshot.current.checked_at_unix * 1000).toLocaleString(Qt.locale(panel.language)) : panel.tr("Нет проверенной версии списков", "No verified snapshot")
    }
    Label {
        visible: !!panel.snapshot.previous
        text: panel.tr("Предыдущая версия: ", "Previous version: ") + (panel.snapshot.previous ? panel.snapshot.previous.version : "")
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: panel.snapshot.current_error || panel.snapshot.previous_error
        text: panel.tr("Текущая или резервная версия недоступна. Проверьте статус операции.", "Current or previous snapshot unavailable. Check operation status.")
    }
    CheckBox {
        objectName: "presetActivate"
        text: panel.tr("Использовать свой список", "Use custom list")
        checked: !panel.builtinSelected && !!panel.routing.ru_direct && panel.routing.ru_direct.enabled
        enabled: !panel.snapshot.busy && panel.pendingRequest === 0 && (!!panel.snapshot.current || checked)
        onClicked: panel.command({command: "preset_activate", enabled: checked, expected_revision: panel.routingRevision, request_id: panel.nextRequest()})
    }
    Button {
        text: panel.tr("Использовать текущую версию", "Use current version")
        enabled: !!panel.snapshot.current && !panel.snapshot.busy && panel.pendingRequest === 0
        onClicked: panel.command({command: "preset_activate", enabled: true, expected_revision: panel.routingRevision, request_id: panel.nextRequest()})
    }
    CheckBox { objectName: "presetConfigure"; id: configure; text: panel.tr("Настроить источник", "Configure source") }
    ColumnLayout {
        visible: configure.checked
        Layout.fillWidth: true
        TextField { objectName: "presetVersion"; id: version; placeholderText: panel.tr("Общая версия выпуска", "Shared release version"); maximumLength: 128; Layout.fillWidth: true }
        TextField { objectName: "presetDomainsURL"; id: domains; placeholderText: panel.tr("URL доменного списка", "Domain list URL"); maximumLength: 8192; Layout.fillWidth: true }
        TextField { objectName: "presetDomainHash"; id: domainHash; placeholderText: panel.tr("SHA256 доменного списка", "Domain list SHA256"); maximumLength: 64; Layout.fillWidth: true }
        TextField { objectName: "presetIpsURL"; id: ips; placeholderText: panel.tr("URL списка CIDR", "CIDR list URL"); maximumLength: 8192; Layout.fillWidth: true }
        TextField { objectName: "presetIpHash"; id: ipHash; placeholderText: panel.tr("SHA256 списка CIDR", "CIDR list SHA256"); maximumLength: 64; Layout.fillWidth: true }
        ComboBox { objectName: "presetFetchRoute"; id: fetchRoute; model: ["Proxy", "Direct"] }
        CheckBox { objectName: "presetLocal"; id: local; text: panel.tr("Явно разрешить локальный HTTP/LAN источник", "Explicitly allow local HTTP/LAN source") }
        Button {
            objectName: "presetUpdateButton"
            text: panel.tr("Обновить списки", "Update lists")
            enabled: !panel.snapshot.busy && panel.pendingRequest === 0
            onClicked: {
                const revision = version.text
                panel.command({command: "preset_update", request_id: panel.nextRequest(), route: fetchRoute.currentIndex === 0 ? "proxy" : "direct", local_exception: local.checked,
                    metadata: {source_id: "ru-direct", version: revision, format: "plain-domain-cidr-v1", enabled: false, checked_at_unix: Math.floor(Date.now() / 1000),
                        domains: {url: domains.text, revision: revision, sha256: domainHash.text}, ips: {url: ips.text, revision: revision, sha256: ipHash.text}}})
                domains.clear(); ips.clear()
            }
        }
    }
    Button {
        objectName: "presetCancelButton"
        text: panel.tr("Отменить обновление", "Cancel update")
        visible: panel.snapshot.busy
        onClicked: panel.command({command: "preset_cancel", request_id: panel.snapshot.active_request_id})
    }
    Button {
        objectName: "presetValidateButton"
        text: panel.tr("Проверить списки в ядре", "Validate lists in engine")
        enabled: !panel.snapshot.busy && panel.pendingRequest === 0
        onClicked: panel.command({command: "preset_validate", expected_revision: panel.routingRevision, request_id: panel.nextRequest()})
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: !!panel.snapshot.compiler_error || !!panel.snapshot.operation_error
        text: panel.snapshot.compiler_error || ({invalid_ip: panel.tr("Введите корректный IP-адрес или домен", "Enter a valid IP address or domain"), storage: panel.tr("Хранилище недоступно", "Storage unavailable"), busy: panel.tr("Хранилище занято", "Storage busy"), integrity: panel.tr("Нарушена целостность snapshot", "Snapshot integrity failure")})[panel.snapshot.operation_error] || ""
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: panel.snapshot.host_validated === true
        text: panel.tr("Config-check Host пройден; native TUN не проверен", "Host config-check passed; native TUN not tested")
    }
    Label { objectName: "presetFeedback"; Layout.fillWidth: true; wrapMode: Text.Wrap; text: panel.feedbackText(panel.feedback); visible: !!text }
    RowLayout {
        Button { objectName: "presetStatusButton"; text: panel.tr("Проверить версии", "Check versions"); onClicked: panel.command({command: "preset_status"}) }
        Button { objectName: "presetRollbackButton"; text: panel.tr("Откатить", "Roll back"); enabled: !!panel.snapshot.previous && !panel.snapshot.busy; onClicked: panel.command({command: "preset_rollback", request_id: panel.nextRequest()}) }
    }
    TextField {
        id: target
        objectName: "presetTarget"
        Layout.fillWidth: true
        placeholderText: panel.tr("IP-адрес или домен", "IP address or domain")
        maximumLength: 253
    }
    Button {
        objectName: "presetPrepareButton"
        text: panel.tr("Проверить маршрут", "Check route")
        enabled: (panel.builtinSelected && panel.routing.ru_direct.enabled || !!panel.snapshot.current) && !panel.snapshot.busy
        onClicked: panel.command({command: "preset_prepare", target: target.text, request_id: panel.nextRequest()})
    }
    Label {
        objectName: "presetDecision"
        visible: panel.snapshot.prepared === true
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: (!panel.routing.ru_direct ? panel.tr("Предпросмотр неактивированного snapshot. ", "Preview of inactive snapshot. ") : panel.tr("Модель сохранённого черновика. ", "Saved draft model. ")) + panel.feedbackText(panel.snapshot.decision || "") + " · " + panel.tr("Решение evaluator. Проверка ядром и Host Apply не выполнена.", "Evaluator decision. Engine validation and Host Apply have not run.")
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: panel.tr("Списки сохраняются в черновике. После обновления активируйте новую версию.", "The lists are saved in the draft. Activate the new version after updating.")
    }
}
