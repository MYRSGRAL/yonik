import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: form
    objectName: "manualEntryDialog"
    property bool english: false
    signal submitted(string name, string text)
    modal: true
    title: tr("Сервер вручную", "Manual server")
    width: Math.min(parent.width - 32, 540)
    height: Math.min(parent.height - 32, 720)
    anchors.centerIn: parent
    function tr(ru, en) { return english ? en : ru }
    property string protocol: protocolInput.currentValue || "vless"
    property bool identity: protocol === "vless" || protocol === "vmess"
    property bool transports: identity || protocol === "trojan"
    property bool tlsAllowed: transports || protocol === "http"
    function bounded(value, required) {
        return (!required || value.length > 0) && value.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(value)
    }
    function localPlaintextHost() {
        const parts = host.text.split(".")
        if (host.text === "::1") return true
        if (parts.length !== 4 || !parts.every(function(v) { return /^[0-9]{1,3}$/.test(v) && Number(v) <= 255 })) return false
        return parts[0] === "127" || parts[0] === "10"
            || (parts[0] === "192" && parts[1] === "168")
            || (parts[0] === "169" && parts[1] === "254")
            || (parts[0] === "172" && Number(parts[1]) >= 16 && Number(parts[1]) <= 31)
    }
    function valid() {
        return (protocol !== "trojan" || tls.checked)
            && (protocol !== "vless" || tls.checked || localPlaintextHost())
            && bounded(serverName.text.trim(), true) && serverName.text.trim().length <= 128
            && bounded(host.text, true) && !/[\s/?#@%\[\]\\]/.test(host.text)
            && /^[0-9]+$/.test(port.text) && Number(port.text) > 0 && Number(port.text) <= 65535
            && (!identity || /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(uuid.text))
            && (!(protocol === "trojan" || protocol === "shadowsocks") || bounded(password.text, true))
            && bounded(password.text, false) && bounded(username.text, false)
            && (!(protocol === "http" || protocol === "socks") || (!!username.text === !!password.text))
            && bounded(sni.text, false) && !/[\s/?#@%\[\]\\]/.test(sni.text)
            && bounded(alpn.text, false) && (!alpn.text || alpn.text.split(",").every(function(v) { return /^[a-zA-Z0-9./-]+$/.test(v) }))
            && bounded(path.text, false) && (!path.text || path.text[0] === "/")
            && bounded(wsHost.text, false) && !/[\s/?#@%\[\]\\]/.test(wsHost.text)
            && bounded(service.text, false)
    }
    function payload() {
        const outbound = Object.create(null)
        outbound.type = protocol
        outbound.tag = serverName.text.trim()
        outbound.server = host.text
        outbound.server_port = Number(port.text)
        if (identity) outbound.uuid = uuid.text
        if (protocol === "vmess") { outbound.security = cipher.currentText; outbound.alter_id = 0 }
        if (protocol === "shadowsocks") outbound.method = method.currentText
        if (!identity && password.text) outbound.password = password.text
        if ((protocol === "http" || protocol === "socks") && username.text) outbound.username = username.text
        if (protocol === "socks") outbound.version = "5"
        if (tlsAllowed && tls.checked) {
            outbound.tls = {enabled: true}
            if (sni.text) outbound.tls.server_name = sni.text
            if (alpn.text) outbound.tls.alpn = alpn.text.split(",")
        }
        if (transports && transport.currentIndex > 0) {
            outbound.transport = {type: transport.currentText}
            if (transport.currentText === "ws") {
                if (path.text) outbound.transport.path = path.text
                if (wsHost.text) outbound.transport.headers = {Host: wsHost.text}
            } else if (service.text) outbound.transport.service_name = service.text
        }
        return JSON.stringify({outbounds: [outbound]})
    }
    function clear() {
        for (const field of [serverName, host, port, uuid, username, password, sni, alpn, path, wsHost, service]) field.clear()
        tls.checked = false; transport.currentIndex = 0
        protocolInput.currentIndex = 0; cipher.currentIndex = 0; method.currentIndex = 0
    }
    onClosed: clear()
    onOpened: tls.checked = true
    contentItem: ScrollView {
        clip: true
        ColumnLayout {
            width: parent.width
            spacing: 8
            Label { text: form.tr("Протокол", "Protocol") }
            ComboBox { id: protocolInput; objectName: "manualProtocol"; Layout.fillWidth: true; textRole: "label"; valueRole: "value"; model: [
                {label:"VLESS",value:"vless"}, {label:"VMess",value:"vmess"}, {label:"Trojan",value:"trojan"},
                {label:"Shadowsocks",value:"shadowsocks"}, {label:"SOCKS",value:"socks"}, {label:"HTTP",value:"http"}]
                delegate: ItemDelegate {
                    required property var modelData
                    required property int index
                    objectName: "manualProtocolChoice_" + index
                    width: protocolInput.width
                    text: modelData.label
                    highlighted: protocolInput.highlightedIndex === index
                }
                onActivated: { tls.checked = form.protocol === "trojan" || form.protocol === "vless"; transport.currentIndex = 0; uuid.clear(); username.clear(); password.clear(); sni.clear(); alpn.clear(); path.clear(); wsHost.clear(); service.clear() }
            }
            Label { visible: true; text: form.tr("Название", "Name") }
            TextField { id: serverName; objectName: "manual_serverName"; visible: true; Layout.fillWidth: true; maximumLength: 128; Accessible.name: form.tr("Название", "Name"); }
            Label { visible: true; text: form.tr("Адрес сервера", "Server address") }
            TextField { id: host; objectName: "manual_host"; visible: true; Layout.fillWidth: true; maximumLength: 253; Accessible.name: form.tr("Адрес сервера", "Server address"); }
            Label { visible: true; text: form.tr("Порт", "Port") }
            TextField { id: port; objectName: "manual_port"; visible: true; Layout.fillWidth: true; maximumLength: 5; Accessible.name: form.tr("Порт", "Port"); }
            Label { visible: form.identity; text: form.tr("UUID", "UUID") }
            TextField { id: uuid; objectName: "manual_uuid"; visible: form.identity; Layout.fillWidth: true; maximumLength: 36; Accessible.name: form.tr("UUID", "UUID"); echoMode: TextInput.Password; inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText; }
            Label { visible: form.protocol === "http" || form.protocol === "socks"; text: form.tr("Пользователь", "Username") }
            TextField { id: username; objectName: "manual_username"; visible: form.protocol === "http" || form.protocol === "socks"; Layout.fillWidth: true; maximumLength: 1024; Accessible.name: form.tr("Пользователь", "Username"); echoMode: TextInput.Password; inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText; }
            Label { visible: !form.identity; text: form.tr("Пароль", "Password") }
            TextField { id: password; objectName: "manual_password"; visible: !form.identity; Layout.fillWidth: true; maximumLength: 1024; Accessible.name: form.tr("Пароль", "Password"); echoMode: TextInput.Password; inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText; }
            Label { visible: form.protocol === "vmess"; text: form.tr("Шифр VMess", "VMess cipher") }
            ComboBox { id: cipher; objectName: "manualCipher"; visible: form.protocol === "vmess"; model: ["auto", "aes-128-gcm", "chacha20-poly1305", "none"] }
            Label { visible: form.protocol === "shadowsocks"; text: form.tr("Шифр Shadowsocks", "Shadowsocks cipher") }
            ComboBox { id: method; objectName: "manualMethod"; visible: form.protocol === "shadowsocks"; model: ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] }
            Label { visible: form.protocol === "trojan" || (form.protocol === "vless" && !form.localPlaintextHost()); text: form.tr("Для этого сервера требуется TLS", "This server requires TLS") }
            CheckBox { id: tls; objectName: "manualTls"; visible: form.tlsAllowed; text: "TLS"; onToggled: if (!checked) { sni.clear(); alpn.clear() } }
            Label { visible: form.tlsAllowed && tls.checked; text: form.tr("Имя TLS (SNI)", "TLS name (SNI)") }
            TextField { id: sni; objectName: "manual_sni"; visible: form.tlsAllowed && tls.checked; Layout.fillWidth: true; maximumLength: 253; Accessible.name: form.tr("Имя TLS (SNI)", "TLS name (SNI)") }
            Label { visible: form.tlsAllowed && tls.checked; text: form.tr("ALPN через запятую", "Comma-separated ALPN") }
            TextField { id: alpn; objectName: "manual_alpn"; visible: form.tlsAllowed && tls.checked; Layout.fillWidth: true; maximumLength: 256; Accessible.name: form.tr("ALPN через запятую", "Comma-separated ALPN") }
            Label { visible: form.transports; text: form.tr("Транспорт", "Transport") }
            ComboBox { id: transport; objectName: "manualTransport"; visible: form.transports; model: ["tcp", "ws", "grpc"];
                delegate: ItemDelegate {
                    required property var modelData
                    required property int index
                    objectName: "manualTransportChoice_" + index
                    width: transport.width
                    text: modelData
                    highlighted: transport.highlightedIndex === index
                }
                onActivated: { path.clear(); wsHost.clear(); service.clear() } }
            Label { visible: form.transports && transport.currentIndex === 1; text: form.tr("Путь WS", "WS path") }
            TextField { id: path; objectName: "manual_path"; visible: form.transports && transport.currentIndex === 1; Layout.fillWidth: true; maximumLength: 1024; Accessible.name: form.tr("Путь WS", "WS path") }
            Label { visible: form.transports && transport.currentIndex === 1; text: form.tr("Host WS", "WS Host") }
            TextField { id: wsHost; objectName: "manual_wsHost"; visible: form.transports && transport.currentIndex === 1; Layout.fillWidth: true; maximumLength: 1024; Accessible.name: form.tr("Host WS", "WS Host") }
            Label { visible: form.transports && transport.currentIndex === 2; text: form.tr("Сервис gRPC", "gRPC service") }
            TextField { id: service; objectName: "manual_service"; visible: form.transports && transport.currentIndex === 2; Layout.fillWidth: true; maximumLength: 1024; Accessible.name: form.tr("Сервис gRPC", "gRPC service") }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: form.tr("Сервер появится после проверки импорта.", "The server will appear after import review.") }
            RowLayout {
                Button { objectName: "manualCancel"; text: form.tr("Отмена", "Cancel"); onClicked: form.close() }
                Button { objectName: "manualSubmit"; text: form.tr("Проверить", "Review"); enabled: form.valid(); onClicked: { form.submitted(serverName.text.trim(), form.payload()); form.close() } }
            }
        }
    }
}
