#include "application.h"
#include <QGuiApplication>
#include <QFont>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QVariant>
#include <atomic>

namespace yonik_bench {
namespace {
QQuickWindow* window = nullptr;
std::atomic<std::int32_t> requested{0};
std::int32_t synchronizedToken = 0;
std::atomic<std::uint64_t> frames{0};
}

std::uint64_t rendered_frames() { return frames.load(std::memory_order_acquire); }

void request_probe(std::uint64_t nonce)
{
    if (window) QMetaObject::invokeMethod(window, "probe", Qt::DirectConnection,
        Q_ARG(QVariant, QVariant(QString::number(nonce))));
}

void request_frame(std::int32_t token)
{
    requested.store(token, std::memory_order_release);
    if (window) window->update();
}

void resume_for_show()
{
    if (window && !window->isVisible()) window->show();
}

void exit_application()
{
    QCoreApplication::quit();
}

int run_application()
{
    int argc = 1;
    char name[] = "yonik-bench-qt";
    char* argv[] = {name, nullptr};
    QGuiApplication app(argc, argv);
    QGuiApplication::setQuitOnLastWindowClosed(false);
    QFont font(QStringLiteral("Noto Sans"));
    font.setPixelSize(14);
    QGuiApplication::setFont(font);
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QQmlApplicationEngine engine;
    engine.loadFromModule("yonik.benchmark", "Main");
    if (engine.rootObjects().isEmpty()) return 1;
    window = qobject_cast<QQuickWindow*>(engine.rootObjects().first());
    if (!window) return 1;
    // beforeSynchronizing выполняется после остановки GUI thread: token относится
    // именно к синхронизированному layout, а не к предыдущему кадру в полёте.
    QObject::connect(window, &QQuickWindow::beforeSynchronizing, window, [] {
        synchronizedToken = requested.load(std::memory_order_acquire);
    }, Qt::DirectConnection);
    QObject::connect(window, &QQuickWindow::frameSwapped, window, [quick = window] {
        const auto count = frames.load(std::memory_order_relaxed);
        frames.store(count == UINT64_MAX ? count : count + 1, std::memory_order_release);
        const auto token = synchronizedToken;
        QMetaObject::invokeMethod(quick, "acknowledgeFrame", Qt::QueuedConnection,
                                  Q_ARG(QVariant, QVariant(token)));
    }, Qt::DirectConnection);
    const int result = app.exec();
    window = nullptr;
    return result;
}
}
