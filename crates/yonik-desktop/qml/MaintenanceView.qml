import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

ColumnLayout {
    id: root
    required property var sendCommand
    required property var errorText
    property bool english: false
    property bool available: false
    property int revision: 0
    property var response: null
    required property var nextRequestId
    property double pending: 0
    property string operation: "backup"
    property string sourcePath: ""
    property string destinationPath: ""
    property string feedback: ""
    readonly property bool busy: pending !== 0
    function tr(ru, en) { return english ? en : ru }
    function localPath(url) {
        const value = url.toString()
        if (!value.startsWith("file:///")) return ""
        try { return decodeURIComponent(value.slice(7)) } catch (_) { return "" }
    }
    function submit() {
        if (busy || !available) return
        if ((operation === "restore" && !sourcePath) || !destinationPath) return
        pending = nextRequestId()
        feedback = tr("Подготовка копии…", "Preparing copy…")
        if (operation === "restore") {
            sendCommand({command: "maintenance_start", request_id: pending,
                operation: operation, source: sourcePath, destination: destinationPath, revision: revision})
        } else {
            sendCommand({command: "maintenance_start", request_id: pending,
                operation: operation, destination: destinationPath, revision: revision})
        }
    }
    onResponseChanged: {
        if (!response || response.request_id !== pending) return
        if (response.phase === "complete" || response.phase === "failed") {
            pending = 0
            feedback = response.error ? errorText(response.error)
                : tr("Зашифрованная копия сохранена в выбранный новый файл.", "Encrypted copy saved to the selected new file.")
        } else if (response.phase === "cancelling") {
            feedback = tr("Отмена: ожидается освобождение файлов.", "Cancelling: waiting for files to be released.")
        }
    }
    spacing: 10
    Label {
        Layout.fillWidth: true
        text: root.tr("Резервная копия", "Backup")
        font.pixelSize: 21
        font.weight: Font.DemiBold
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: root.tr("Для восстановления нужен тот же ключ системного хранилища. Восстановление создаёт отдельный файл.", "Restoring requires the same system key. Restore creates a separate file.")
    }
    Button {
        objectName: "maintenanceBackup"
        Layout.fillWidth: true
        highlighted: true
        text: root.tr("Создать зашифрованную копию…", "Create encrypted backup…")
        enabled: root.available && !root.busy
        onClicked: { root.operation = "backup"; destination.open() }
    }
    Button {
        objectName: "maintenanceRestore"
        Layout.fillWidth: true
        text: root.tr("Восстановить из копии…", "Restore from backup…")
        enabled: root.available && !root.busy
        onClicked: { root.operation = "restore"; source.open() }
    }
    Button {
        objectName: "maintenanceCancel"
        visible: root.busy
        text: root.tr("Отменить", "Cancel")
        onClicked: root.sendCommand({command: "maintenance_cancel", request_id: root.pending})
    }
    Label {
        objectName: "maintenanceFeedback"
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: !!root.feedback
        text: root.feedback
    }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        visible: !!root.feedback && !root.busy
        text: root.tr("При ошибке записи проверьте выбранный файл. Существующие файлы не заменяются.", "If writing fails, check the selected file. Existing files are never replaced.")
    }
    FileDialog {
        id: source
        objectName: "maintenanceSourceDialog"
        title: root.tr("Выберите зашифрованную копию", "Select encrypted backup")
        fileMode: FileDialog.OpenFile
        onAccepted: {
            root.sourcePath = root.localPath(selectedFile)
            if (root.sourcePath) destination.open()
            else root.feedback = root.errorText("invalid_input")
        }
    }
    FileDialog {
        id: destination
        objectName: "maintenanceDestinationDialog"
        title: root.tr("Новый файл в приватном каталоге (0700)", "New file in a private directory (0700)")
        fileMode: FileDialog.SaveFile
        onAccepted: {
            root.destinationPath = root.localPath(selectedFile)
            if (root.destinationPath) root.submit()
            else root.feedback = root.errorText("invalid_input")
        }
    }
}
