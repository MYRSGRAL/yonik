# Пакет helper для OpenRC и runit

`stage.sh` собирает дерево пакета из обычных Linux-бинарников `yonik-helper`
и `yonik-worker`. Укажите существующий каталог сборки пакета и пути к обоим
бинарникам.

```sh
packaging/standalone/stage.sh openrc "$pkgdir" "$helper" "$worker"
```

Для runit передайте `runit` первым аргументом. Файлы установленного пакета
должны принадлежать root. Перед запуском служба установки пакета должна
обработать `/usr/lib/sysusers.d/yonik-worker.conf` штатным механизмом
sysusers дистрибутива или создать указанную системную учётную запись и группу.
Используется обычная конфигурация доверенных движков Yonik.

Для helper нужны системный D-Bus, polkit, nftables, TUN и cgroup v2
с `cgroup.kill`. Файловая изоляция использует рекурсивные mount-атрибуты,
а фильтр системных вызовов устанавливает `setpriv --seccomp-filter`.
Эти возможности доступны в util-linux 2.41 и новее при соответствующей
конфигурации сборки. Helper создаёт защищённые каталоги в `/run`.
[Документация setpriv](https://raw.githubusercontent.com/util-linux/util-linux/v2.41/sys-utils/setpriv.1.adoc)

При старте helper проверяет устройство `/dev/net/tun`. Если его ещё нет,
helper вызывает штатный `/sbin/modprobe tun`. Polkit активируется через
системный D-Bus перед публикацией сервиса Yonik.

OpenRC ставит сценарий в `/etc/init.d/yonik-helper`. Он запускает helper
после D-Bus и управляет процессом через `supervise-daemon`.

```sh
rc-update add yonik-helper default
rc-service yonik-helper start
```

Для runit добавьте `/etc/sv/yonik-helper` в активный каталог `runsvdir`
дистрибутива. В примере используется каталог `/var/service`.

```sh
ln -s /etc/sv/yonik-helper /var/service/yonik-helper
sv start /var/service/yonik-helper
sv -w 70 down /var/service/yonik-helper
```

D-Bus использует общую политику доступа Yonik. Имя службы публикует
процесс, запущенный OpenRC или runit. При штатной остановке helper завершает
worker перед удалением сетевой сессии и сохраняет действующий карантин Fake-IP.
Системный TUN и scoped Fake DNS доступны через обычный API. Атрибуция
приложений и транспорт канонических ресурсов требуют systemd.

Для управления из графического клиента polkit должен видеть активную
локальную сессию. В OpenRC и runit сведения о сеансе может предоставлять
elogind. [Политика активных сеансов](https://polkit.pages.freedesktop.org/polkit/polkit.8.html) · [Документация elogind](https://github.com/elogind/elogind)
