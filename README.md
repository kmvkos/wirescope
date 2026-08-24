# WireScope

Сетевой аудитор под Linux: Debian/Ubuntu, Fedora/RHEL/Rocky, openSUSE.
amd64 или arm64. Raspberry Pi не обязателен, Raspberry Pi OS не нужна.

Ставится на отдельный хост или ВМ. Смотрит локальную сеть: пассивный захват,
scope который подтверждает оператор, активное обнаружение только внутри него,
проверки протоколов, находки, HTML-отчёт.

GUI на русском. GNOME, XFCE, KDE не ставятся. После загрузки киоск занимает
tty1 и открывает Chromium на `http://127.0.0.1:8000/`.

Репозиторий на GitHub приватный:
https://github.com/kmvkos/wirescope

## Клон и установка

Установщик работает из клона (venv, frontend, скрипты киоска). Сам он дерево
в `/opt/wirescope` не копирует. Данные: `/var/lib/wirescope`. Конфиг:
`/etc/wirescope`. `--project-root` по умолчанию это каталог, где лежит
`packaging/`.

```bash
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
sudo ./packaging/install.sh --with-kiosk --enable-kiosk
```

`sudo git clone` использует ключи root. Если ключ у вашего пользователя,
клонируйте без `sudo`, потом `sudo mv wirescope /opt/wirescope`. Или ставьте
из другого каталога:

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --bind-host 127.0.0.1 \
  --with-kiosk --enable-kiosk
```

Этот клон после установки не удалять и не переименовывать. Юниты systemd
указывают на него.

HTTPS:

```bash
git clone https://github.com/kmvkos/wirescope.git
```

Для приватного репозитория GitHub просит логин и токен, не пароль аккаунта.

`--with-kiosk` ставит Cage или Xorg/`xinit` и Chromium. Не GNOME. `--enable-kiosk`
включает юнит на `multi-user.target`. Если пакеты уже стоят:

```bash
sudo ./packaging/install.sh --skip-packages --enable-kiosk
# или
sudo systemctl enable --now wirescope-kiosk
```

Перезагрузите машину с консолью, не только по SSH. На tty1 откроется Chromium.
SSH для админки не трогается.

Без постоянного root можно поставить в user systemd:

```bash
./packaging/install.sh --user-install --bind-host 127.0.0.1
```

`dumpcap` всё равно один раз настраивается от root. Данные тогда в
`~/.local/share/wirescope`, конфиг в `~/.config/wirescope`, юниты в
`~/.config/systemd/user`. Управление: `systemctl --user`. Пакеты ОС этот режим
не ставит.

`--bind-host` задаёт адрес API. По умолчанию `127.0.0.1:8000`. Для доступа
с другого ПК API лучше оставить на loopback, TLS терминировать на Caddy или
nginx (`--trust-proxy`). HTTP на `0.0.0.0:8000` в LAN лучше не открывать.

На VMware киоск идёт через Xorg. Cage там зависает на чёрном экране. Если
консоль чёрная и нет ни login, ни Chromium, киоск занял tty1 и не открыл
дисплей. По SSH: `sudo systemctl start getty@tty1`. Дальше
`sudo systemctl status wirescope-kiosk`.

## Киоск и браузер

Киоск: дисплей этой машины, `http://127.0.0.1:8000/`. Сеть до вашего ПК
не нужна.

С другого ПК: HTTPS через Caddy или nginx, API на loopback. См.
[packaging/proxy/README.md](packaging/proxy/README.md).

На интерфейсе захвата IP может не быть. GUI от этого не зависит, он локальный.

## auditor и пользователь Linux

Это разные учётки.

`wirescope` в Linux: установка, `sudo`, службы.

`auditor` только в веб-интерфейсе (киоск или браузер). В консоль Linux под
`auditor` не входите.

## Тесты

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -m "not network"
```

Маркер `network` может трогать живую сеть. Pytest его и так пропускает,
вместе с `live_pi`. Тесты Raspberry Pi OS Lite на обычном Linux не нужны.

Нужны Python 3.11+, `ip` (iproute2), `dumpcap`, `tshark`.

Активное сканирование только внутри scope, который подтвердил оператор.
`0.0.0.0/0`, `::/0` и multicast отклоняются. Backend не от root. Capabilities
на захват пакетов есть только у `/usr/bin/dumpcap`.

## Документация

[установка](docs/INSTALLATION.md),
[безопасность](docs/SECURITY_MODEL.md),
[runbook](docs/RUNBOOK.md),
[архитектура](docs/ARCHITECTURE.md).
