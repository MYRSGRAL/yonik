import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: view
    property bool english: false
    property var entries: []
    property string selectedText: ""
    function tr(ru, en) { return english ? en : ru }
    function resource(name) {
        if (name !== "index" && !/^[0-9a-f]{64}$/.test(name)) return null
        let component = Qt.createComponent("qrc:/notices/" + name + ".qml", Component.PreferSynchronous)
        return component.status === Component.Ready ? component.createObject(view) : null
    }
    function readResource(hash) {
        if (!/^[0-9a-f]{64}$/.test(hash)) return ""
        let object = resource(hash)
        if (!object) return ""
        let text = object.noticeText
        object.destroy()
        return text
    }
    Component.onCompleted: {
        let object = resource("index")
        if (object) { entries = object.entries; object.destroy() }
    }
    Label {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: view.tr("Лицензии приложения и компонентов. Состав зависит от варианта сборки. Версии и уведомления смотрите в списке ниже.", "Application and component licenses. Contents depend on the build variant. See the list below for versions and notices.")
    }
    TextField {
        id: search
        objectName: "noticesSearch"
        Layout.fillWidth: true
        maximumLength: 256
        placeholderText: view.tr("Поиск компонента", "Search components")
    }
    ListView {
        objectName: "noticesList"
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.minimumHeight: 100
        clip: true
        model: view.entries.filter(item => (item.name + " " + item.version).toLowerCase().indexOf(search.text.toLowerCase()) >= 0)
        delegate: ItemDelegate {
            required property var modelData
            width: ListView.view.width
            contentItem: Label { text: modelData.name + " " + modelData.version + " · " + modelData.scope; textFormat: Text.PlainText; elide: Text.ElideRight }
            onClicked: view.selectedText = modelData.hashes.map(hash => view.readResource(hash)).join("\n\n")
        }
        ScrollBar.vertical: ScrollBar {}
    }
    ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.minimumHeight: 120
        TextArea {
            objectName: "noticesText"
            readOnly: true
            selectByMouse: true
            textFormat: TextEdit.PlainText
            wrapMode: TextEdit.Wrap
            text: view.selectedText || view.tr("Выберите компонент для просмотра первичных уведомлений.", "Select a component to read its primary notices.")
        }
    }
}
