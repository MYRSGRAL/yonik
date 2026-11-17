import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: root
    required property var backend
    property bool english: false
    spacing: 12
    function tr(ru, en) { return root.english ? en : ru }
    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        text: tr("Для поддержки скопируйте безопасные метаданные последней ошибки. Секреты и исходный текст событий не включаются.", "Copy safe metadata from the latest error for support. Secrets and original event text are not included.")
    }
    Button {
        objectName: "copyDiagnosticsButton"
        text: tr("Скопировать для поддержки", "Copy for support")
        onClicked: result.text = root.backend.copy_diagnostics_v2()
            ? (tr("Скопировано", "Copied"))
            : (tr("Экспорт недоступен: нет проверенных метаданных этой ошибки.", "Export unavailable: verified metadata for this error are missing."))
    }
    Label { id: result; objectName: "diagnosticsExportResult"; Layout.fillWidth: true; wrapMode: Text.Wrap }
}
