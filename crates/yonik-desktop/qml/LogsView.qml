import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: root
    objectName: "logsView"
    property string status: root.page ? root.page.status : ""
    required property var backend
    property bool english: false
    property var response: null
    property var page: null
    property string pending: ""
    property bool saving: false
    property string saveStatus: ""
    property int serial: 0
    property bool stale: true
    spacing: 10
    function tr(ru, en) { return root.english ? en : ru }
    function productCode(code) {
        switch (code) {
        case "StartRequested": return tr("Запрошен запуск", "Start requested")
        case "ProcessSpawned": return tr("Процесс запущен", "Process spawned")
        case "StopRequested": return tr("Запрошена остановка", "Stop requested")
        case "CleanupConfirmed": return tr("Очистка подтверждена", "Cleanup confirmed")
        case "CleanupFailed": return tr("Ошибка очистки", "Cleanup failed")
        case "ProcessExited": return tr("Процесс завершён", "Process exited")
        case "NativeSingStarted": case "NativeXrayStarted": return tr("Ядро сообщило о запуске", "Core reported startup")
        case "NativeSingMissingInterface": return tr("Ядро сообщило об отсутствии интерфейса", "Core reported missing interface")
        case "NativeXrayLocalDns": return tr("Ядро создало локальный DNS-клиент", "Core created local DNS client")
        default: return tr("Неизвестное событие", "Unknown event")
        }
    }
    function read(next) {
        root.saving = false
        root.serial += 1
        root.pending = String(root.serial)
        root.stale = true
        root.backend.dispatch(JSON.stringify({command: "logs_read", after: next && root.page ? root.page.cursor : "0", source: source.currentIndex === 1 ? "app" : source.currentIndex === 2 ? "engine" : "all", request_id: root.pending}))
    }
    onResponseChanged: {
        if (root.visible && root.pending !== "" && root.response && root.response.request_id === root.pending) {
            if (root.saving) {
                if (root.response.status === "saving") return
                root.saveStatus = root.response.status
                root.saving = false
                root.pending = ""
                return
            }
            root.page = root.response
            root.pending = ""
            root.stale = root.page.status !== "ready" && root.page.status !== "empty"
        }
    }
    Label { text: root.tr("Журнал событий", "Event log") }
    ComboBox {
        id: source
        objectName: "logsSource"
        model: [root.tr("Все", "All"), root.tr("Приложение", "Application"), root.tr("Движок", "Engine")]
        onActivated: { root.pending = ""; root.stale = true }
    }
    RowLayout {
        Button { objectName: "logsRefresh"; text: root.tr("Открыть / обновить", "Open / refresh"); onClicked: root.read(false) }
        Button { objectName: "logsNext"; text: root.tr("Далее", "Next"); enabled: root.pending === "" && !root.stale && !!root.page; onClicked: root.read(true) }
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: root.pending !== "" ? root.tr("Чтение…", "Reading…") : root.stale ? root.tr("Требуется обновление", "Refresh required") : root.page && root.page.status === "empty" ? root.tr("Нет событий", "No events") : root.tr("Страница готова", "Page ready")
    }
    Label {
        visible: !!root.page && root.page.status === "cancelled"
        text: root.tr("Чтение отменено. Повторите запрос.", "Reading cancelled. Retry request.")
    }
    Label {
        visible: !!root.page && root.page.status === "busy"
        text: root.tr("Журнал занят. Повторите чтение.", "Log busy. Retry reading.")
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: root.page ? root.tr("Курсор · удалено · отклонено · пропущено: ", "Cursor · evicted · rejected · missed: ") + [root.page.cursor, root.page.evicted, root.page.rejected, root.page.missed].join(" / ") : ""
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        textFormat: Text.PlainText
        objectName: "logsWithheldNotice"
        visible: !!root.page && !root.stale && root.page.rejected !== "0"
        text: root.tr("Неподдерживаемые и неполные сообщения ядра скрываются; исходный текст не сохраняется.", "Unsupported and incomplete core messages are withheld; original input is not stored.")
    }
    ListView {
        objectName: "logsRows"
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.minimumHeight: 120
        clip: true
        model: root.visible && !root.stale && root.page ? root.page.events : []
        delegate: Label {
            required property var modelData
            objectName: modelData.technical_details ? "logsNativeDetails" : ""
            width: ListView.view.width
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: modelData.id + (modelData.session_id ? " [" + modelData.session_id + "/" + modelData.generation + "]" : "") + " · " + (modelData.source === "app" ? root.tr("Приложение", "Application") : root.tr("Движок", "Engine")) + " · " + root.productCode(modelData.code) + (modelData.value === null ? "" : " · " + modelData.value) + (modelData.technical_details ? "\n" + root.tr("Технические детали: ", "Technical details: ") + modelData.technical_details : "")
        }
    }
    TextField {
        id: destination
        objectName: "logsDestination"
        Layout.fillWidth: true
        placeholderText: root.tr("Путь к новому файлу", "Path to a new file")
        maximumLength: 4096
    }
    Button {
        objectName: "logsSave"
        text: root.tr("Сохранить страницу", "Save page")
        enabled: root.pending === "" && !root.stale && !!root.page && destination.text !== ""
        onClicked: {
            if (!root.visible || root.stale || root.pending !== "" || !root.page) return
            root.serial += 1
            root.pending = String(root.serial)
            root.saving = true
            root.saveStatus = ""
            root.backend.dispatch(JSON.stringify({command: "logs_save", page_request_id: root.page.request_id, request_id: root.pending, destination: destination.text}))
        }
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: root.saveStatus !== ""
        text: root.saveStatus === "saved" ? root.tr("Страница сохранена", "Page saved") : root.saveStatus === "saved_durability_unknown" ? root.tr("Файл создан; долговечность записи не подтверждена", "File created; durability unconfirmed") : root.tr("Сохранение отклонено. Выберите новый файл и обновите страницу.", "Save refused. Choose a new file and refresh the page.")
    }
    TextEdit {
        id: exportText
        objectName: "logsExportText"
        visible: false
        textFormat: TextEdit.PlainText
        text: !root.stale && root.page && root.page.export ? root.page.export : ""
        readOnly: true
    }
    Button {
        objectName: "logsCopy"
        text: root.tr("Копировать страницу", "Copy page")
        enabled: root.pending === "" && !root.stale && exportText.text !== ""
        onClicked: {
            if (!root.visible || root.stale || root.pending !== "" || !root.page || !root.page.export) return
            exportText.selectAll()
            exportText.copy()
            exportText.deselect()
        }
    }
}
