"""Внешняя SNI fixture; инфраструктура, не product tray renderer."""

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus(private=True)
name = dbus.service.BusName("org.kde.StatusNotifierWatcher", bus)


class Watcher(dbus.service.Object):
    @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s")
    def RegisterStatusNotifierItem(self, service: str) -> None:
        """Зарегистрировать actual Qt SNI без извлечения product памяти."""
        print("REGISTERED " + str(service), flush=True)

    @dbus.service.method(
        "org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v"
    )
    def Get(self, interface: str, prop: str) -> object:
        """Опубликовать наличие controlled tray host."""
        return {
            "IsStatusNotifierHostRegistered": dbus.Boolean(True),
            "ProtocolVersion": dbus.Int32(0),
            "RegisteredStatusNotifierItems": dbus.Array([], signature="s"),
        }[prop]


watcher = Watcher(bus, "/StatusNotifierWatcher")
print("READY", flush=True)
GLib.MainLoop().run()
