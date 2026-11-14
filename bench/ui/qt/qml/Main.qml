pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import yonik.benchmark

ApplicationWindow {
    id: root
    width: 800
    height: 640
    minimumWidth: 800
    minimumHeight: 640
    visible: true
    title: "Yonik · Qt Quick"
    color: "#191919"
    font.family: "Noto Sans"
    font.pixelSize: 14
    palette.window: "#191919"
    palette.base: "#222222"
    palette.button: "#292929"
    palette.buttonText: "#eeeeee"
    palette.text: "#eeeeee"
    palette.highlight: "#c3a6ef"
    palette.highlightedText: "#191919"
    property var snapshot: ({page: [], total: 0, offset: 0, search: "", favorites_only: false, sort: "source", selected_id: null})
    property var delegates: ({})
    property int createdTotal: 0
    property int frameToken: 0
    property int pendingToken: 0
    property string pendingEvent: ""
    property int scrollIndex: 0

    function query(offset) {
        bridge.dispatch(JSON.stringify({op: "query", search: search.text, offset: offset,
                                        favorites_only: favorites.checked,
                                        sort: sorting.currentIndex === 0 ? "source" : "name"}))
    }
    function scheduleFrame(event) {
        pendingEvent = event
        pendingToken = ++frameToken
        servers.forceLayout()
        bridge.request_frame(pendingToken)
    }
    function probe(nonce) { report("probe", nonce) }
    function report(event, nonce) {
        let live = 0
        let visibleRows = 0
        for (let key in delegates) {
            let item = delegates[key]
            if (!item) continue
            ++live
            let point = item.mapToItem(servers, 0, 0)
            if (root.visible && item.visible && point.y < servers.height && point.y + item.height > 0)
                ++visibleRows
        }
        if (event === "probe")
            bridge.finish_probe(nonce, createdTotal, live, visibleRows, scrollIndex)
        else
            bridge.finish(event, createdTotal, live, visibleRows, scrollIndex)
    }
    // Вызывается C++ только в GUI thread после frameSwapped нужного token.
    function acknowledgeFrame(token) {
        if (pendingToken === 0 || token !== pendingToken) return
        let event = pendingEvent
        pendingToken = 0
        pendingEvent = ""
        report(event)
    }

    BenchBridge {
        id: bridge
        onSnapshot_jsonChanged: {
            root.snapshot = JSON.parse(bridge.snapshot_json)
            search.text = root.snapshot.search
            favorites.checked = root.snapshot.favorites_only
            sorting.currentIndex = root.snapshot.sort === "name" ? 1 : 0
            root.scrollIndex = 0
            servers.positionViewAtBeginning()
            root.scheduleFrame("frame")
        }
        onControl_jsonChanged: {
            let control = JSON.parse(bridge.control_json)
            if (control.action === "scroll") {
                root.scrollIndex = Math.min(control.index, Math.max(0, servers.count - 1))
                servers.positionViewAtIndex(root.scrollIndex, ListView.Beginning)
                root.scheduleFrame("frame")
            } else if (control.action === "hide") {
                root.hide()
                root.report("hidden")
            } else if (control.action === "show") {
                root.show()
                root.scheduleFrame("shown")
            }
        }
    }
    Component.onCompleted: bridge.initialize()
    onClosing: function(close) {
        close.accepted = false
        bridge.dispatch('{"op":"quit"}')
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: 20
        spacing: 12
        RowLayout {
            spacing: 12
            Layout.fillWidth: true
            Layout.fillHeight: false
            Layout.minimumHeight: 38
            Layout.preferredHeight: 38
            Layout.maximumHeight: 38
            Text { text: "YONIK"; color: "#c3a6ef"; font.family: "Noto Sans"; font.pixelSize: 14; font.bold: true }
            Text { text: "Серверы"; color: "#eeeeee"; font.family: "Noto Sans"; font.pixelSize: 14; Layout.leftMargin: 16 }
            Item { Layout.fillWidth: true }
            Text { text: "Qt Quick · " + root.snapshot.total; color: "#b2b2b2"; font.family: "Noto Sans"; font.pixelSize: 14 }
        }
        RowLayout {
            spacing: 12
            Layout.fillWidth: true
            Layout.fillHeight: false
            Layout.minimumHeight: 40
            Layout.preferredHeight: 40
            Layout.maximumHeight: 40
            TextField {
                id: search
                Layout.fillWidth: true
                placeholderText: "Поиск сервера"
                selectByMouse: true
                onAccepted: root.query(0)
            }
            Button { text: "Найти"; onClicked: root.query(0) }
            ComboBox {
                id: sorting
                model: ["По порядку", "По имени"]
                onActivated: root.query(0)
            }
        }
        RowLayout {
            spacing: 12
            Layout.fillWidth: true
            Layout.fillHeight: false
            Layout.minimumHeight: 40
            Layout.preferredHeight: 40
            Layout.maximumHeight: 40
            CheckBox { id: favorites; text: "Избранные"; onClicked: root.query(0) }
            Item { Layout.fillWidth: true }
            Text {
                text: "Выбран: " + (root.snapshot.selected_id === null ? "—" : root.snapshot.selected_id)
                color: "#b2b2b2"
                font.family: "Noto Sans"
                font.pixelSize: 14
            }
        }
        ListView {
            id: servers
            objectName: "servers"
            Layout.fillWidth: true
            Layout.fillHeight: false
            Layout.minimumHeight: 320
            Layout.preferredHeight: 320
            Layout.maximumHeight: 320
            clip: true
            cacheBuffer: 0
            reuseItems: false
            model: root.snapshot.page
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar {}
            delegate: Rectangle {
                id: row
                required property var modelData
                required property int index
                property int instanceId: 0
                width: servers.width
                height: 66
                color: modelData.id === root.snapshot.selected_id ? "#332b40" : "#191919"
                Component.onCompleted: {
                    instanceId = ++root.createdTotal
                    root.delegates[instanceId] = row
                }
                Component.onDestruction: delete root.delegates[instanceId]
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: "#303030" }
                MouseArea {
                    anchors.fill: parent
                    onClicked: bridge.dispatch(JSON.stringify({op: "select", id: row.modelData.id}))
                }
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12
                    spacing: 14
                    Text { text: row.modelData.country; color: "#c3a6ef"; font.family: "Noto Sans"; font.pixelSize: 14; Layout.minimumWidth: 30; Layout.preferredWidth: 30; Layout.maximumWidth: 30 }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 3
                        Text { text: row.modelData.name; color: "#eeeeee"; font.family: "Noto Sans"; font.pixelSize: 14; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: row.modelData.host; color: "#9c9c9c"; font.family: "Noto Sans"; font.pixelSize: 14; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                    Text { text: row.modelData.latency_ms + " мс"; color: "#c3a6ef"; font.family: "Noto Sans"; font.pixelSize: 14 }
                    Button {
                        text: row.modelData.favorite ? "★" : "☆"
                        flat: true
                        onClicked: bridge.dispatch(JSON.stringify({op: "favorite", id: row.modelData.id, value: !row.modelData.favorite}))
                    }
                }
            }
        }
        RowLayout {
            spacing: 12
            Layout.fillWidth: true
            Layout.fillHeight: false
            Layout.minimumHeight: 40
            Layout.preferredHeight: 40
            Layout.maximumHeight: 40
            Button { text: "Назад"; enabled: root.snapshot.offset > 0; onClicked: root.query(Math.max(0, root.snapshot.offset - 200)) }
            Item { Layout.fillWidth: true }
            Text { text: root.snapshot.offset + " / " + root.snapshot.total; color: "#b2b2b2"; font.family: "Noto Sans"; font.pixelSize: 14 }
            Item { Layout.fillWidth: true }
            Button { text: "Далее"; enabled: root.snapshot.offset + 200 < root.snapshot.total; onClicked: root.query(root.snapshot.offset + 200) }
        }
    }
}
