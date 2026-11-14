// Приватный P02 interposer: actual qrc/bridge и закрытый словарь команд.
#include <QQmlApplicationEngine>
#include <QQuickWindow>
#include <QApplication>
#include <QMenu>
#include <QAction>
#include <QMetaMethod>
#include <QSocketNotifier>
#include <QSystemTrayIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QFile>
#include <QTimer>
#include <sys/socket.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <cerrno>

static std::atomic<bool> capture_enabled{false};
static std::atomic<size_t> captured_bytes{0};

// Сохраняются только успешно принятые kernel bytes pipe, без чтения его потока.
extern "C" ssize_t write(int fd, const void* data, size_t size) {
    const auto result = syscall(SYS_write, fd, data, size);
    const int saved_errno = errno;
    const char* root = getenv("P02_CAPTURE_ROOT");
    if (result > 0 && root && capture_enabled.load()) {
        char path[80], target[80], output[4096];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        const auto count = readlink(path, target, sizeof(target) - 1);
        if (count > 0) {
            target[count] = 0;
            unsigned long inode = 0;
            if (sscanf(target, "pipe:[%lu]", &inode) == 1) {
                if (captured_bytes.fetch_add(result) + result > 10000000) std::abort();
                const int length = snprintf(output, sizeof(output), "%s/pipe-%lu.bin", root, inode);
                if (length < 0 || size_t(length) >= sizeof(output)) std::abort();
                const int artifact = syscall(SYS_openat, AT_FDCWD, output, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
                if (artifact < 0 || syscall(SYS_write, artifact, data, result) != result) std::abort();
                syscall(SYS_close, artifact);
            }
        }
    }
    errno = saved_errno;
    return result;
}


class Observer final : public QObject {
    Q_OBJECT
    QQuickWindow* window;
    QObject* bridge = nullptr;
    QByteArray pending;
    int fd;
    void fail(const char* reason) { qCritical("P02 FAIL %s", reason); QCoreApplication::exit(3); }
    QJsonObject state() const {
        return QJsonDocument::fromJson(bridge->property("snapshot_json").toString().toUtf8()).object();
    }
    void dispatch(QJsonObject value) {
        const auto text = QString::fromUtf8(QJsonDocument(value).toJson(QJsonDocument::Compact));
        if (!QMetaObject::invokeMethod(bridge, "dispatch", Qt::DirectConnection, Q_ARG(QString, text))) fail("actual dispatch");
    }
    void action(const QStringList& names) {
        QAction* found = nullptr;
        for (auto* widget : QApplication::allWidgets()) {
            if (auto* menu = qobject_cast<QMenu*>(widget)) {
                for (auto* item : menu->actions()) if (item->parent() == menu && names.contains(item->text())) {
                    if (found && found != item) { qCritical("P02 duplicate action text=%s menu=%s firstparent=%s secondparent=%s", qPrintable(item->text()), menu->metaObject()->className(), found->parent() ? found->parent()->metaObject()->className() : "null", item->parent() ? item->parent()->metaObject()->className() : "null"); fail("ambiguous QAction"); return; }
                    found = item;
                }
            }
        }
        if (!found || !found->isEnabled()) { fail("missing/disabled actual QAction"); return; }
        found->trigger();
    }
    void command(const QByteArray& value) {
        const auto snapshot = state();
        if (value == "snapshot") changed();
        else if (value == "hide") { window->close(); changed(); }
        else if (value == "connect") { capture_enabled.store(true); action({QStringLiteral("Подключить"), QStringLiteral("Connect")}); }
        else if (value == "stop") action({QStringLiteral("Отключить"), QStringLiteral("Disconnect")});
        else if (value == "quit") action({QStringLiteral("Выйти и отключиться"), QStringLiteral("Quit and Disconnect")});
        else if (value == "selectCore:sing-box" || value == "selectCore:xray")
            dispatch({{"command", "set_engine"}, {"engine", QString::fromUtf8(value.mid(11))}});
        else if (value == "prepareSynthetic") {
            bool valid = false;
            const auto port = qEnvironmentVariableIntValue("P02_PEER_PORT", &valid);
            if (!valid || port < 1 || port > 65535) { fail("fixture port"); return; }
            dispatch({{"command", "import_text"}, {"name", "P02 synthetic"},
                {"text", QStringLiteral("vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:%1#P02").arg(port)}});
        } else if (value == "backup") {
            const auto path = qEnvironmentVariable("P02_BACKUP");
            if (!path.startsWith('/')) { fail("private backup path"); return; }
            dispatch({{"command", "maintenance_start"}, {"request_id", 1}, {"operation", "backup"}, {"destination", path}, {"revision", snapshot["revision"]}});
        } else if (value == "approveSynthetic") dispatch({{"command", "approve_refresh"}});
        else if (value == "selectSynthetic") {
            const auto profiles = snapshot["profiles"].toArray();
            if (profiles.size() != 1) { fail("single synthetic profile"); return; }
            dispatch({{"command", "select_profile"}, {"id", profiles[0].toObject()["id"]}, {"revision", snapshot["revision"]}});
        } else if (value == "healthTarget") {
            bool valid = false;
            const auto port = qEnvironmentVariableIntValue("P02_HEALTH_PORT", &valid);
            if (!valid || port < 1 || port > 65535) { fail("health port"); return; }
            dispatch({{"command", "set_probe_target"}, {"url", QStringLiteral("https://127.0.0.1:%1/").arg(port)}, {"expected_status", 204}});
        } else fail("unknown closed command");
    }
public:
    Observer(QQuickWindow* root, QObject* owner) : QObject(owner), window(root) {
        bool valid = false;
        fd = qEnvironmentVariableIntValue("P02_CONTROL_FD", &valid);
        if (!valid || fd < 3) { fail("private control fd"); return; }
        for (auto* object : root->findChildren<QObject*>())
            if (object->metaObject()->indexOfProperty("snapshot_json") >= 0) {
                if (bridge) { fail("ambiguous actual bridge"); return; }
                bridge = object;
            }
        if (!bridge || root->objectName() != "yonikWindow") { fail("actual window/bridge canary"); return; }
        const auto signal = bridge->metaObject()->indexOfSignal("snapshot_jsonChanged()");
        if (signal < 0) { fail("actual notify canary"); return; }
        QObject::connect(bridge, bridge->metaObject()->method(signal), this, metaObject()->method(metaObject()->indexOfSlot("changed()")));
        auto* notifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
        QObject::connect(notifier, &QSocketNotifier::activated, this, [this] {
            char bytes[4096];
            const auto count = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
            if (count <= 0) { fail("control disconnected"); return; }
            pending.append(bytes, count);
            if (pending.size() > 16384) { fail("control bound"); return; }
            while (pending.contains('\n')) {
                const auto end = pending.indexOf('\n');
                const auto value = pending.left(end); pending.remove(0, end + 1); command(value);
            }
        });
        QTimer::singleShot(0, this, &Observer::changed);
        // Единственный аварийный deadline, никаких периодических test timers.
        QTimer::singleShot(1100000, this, [this] { fail("owned run deadline"); });
    }
private slots:
    void changed() {
        const auto snapshot = state();
        if (snapshot["status"] == "Connected" || snapshot["status"] == "Limited") capture_enabled.store(false);
        const auto record = QJsonDocument(QJsonObject{{"state", snapshot}, {"visible", window->isVisible()},
            {"tray_available", QSystemTrayIcon::isSystemTrayAvailable()}, {"bridge_class", bridge->metaObject()->className()}}).toJson(QJsonDocument::Compact) + '\n';
        if (send(fd, record.constData(), record.size(), MSG_NOSIGNAL | MSG_DONTWAIT) != record.size()) fail("bounded event delivery");
    }
};
void QQmlApplicationEngine::load(const QUrl& url) {
    using Load = void (*)(QQmlApplicationEngine*, const QUrl&);
    const auto original = reinterpret_cast<Load>(dlsym(RTLD_NEXT, "_ZN21QQmlApplicationEngine4loadERK4QUrl"));
    if (!original || url.scheme() != "qrc") std::abort();
    QFile source(":" + url.path());
    if (!source.open(QIODevice::ReadOnly)) std::abort();
    qInfo("P02 MAIN_SHA256 %s", QCryptographicHash::hash(source.readAll(), QCryptographicHash::Sha256).toHex().constData());
    original(this, url);
    if (rootObjects().size() != 1) std::abort();
    auto* window = qobject_cast<QQuickWindow*>(rootObjects().first());
    if (!window) std::abort();
    QTimer::singleShot(0, this, [this, window] { new Observer(window, this); });
}
#include "private_observer.moc"
