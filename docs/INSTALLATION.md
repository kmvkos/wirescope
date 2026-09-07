# Установка WireScope

[English](en/INSTALLATION.md)

WireScope можно установить как отдельный Linux appliance, ВМ или приложение на существующий сервер. Поддерживаются Debian/Ubuntu/Raspberry Pi OS, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`.

## Рекомендуемый system layout

System install запускается из Git checkout и использует:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

Системная установка из `/home/...` или `/root/...` намеренно блокируется. Сгенерированные systemd units используют `ProtectHome=true`, поэтому production checkout должен находиться вне home directory.

## Чистая установка из публичного GitHub

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Не нужно делать `git checkout milestone-*` или выбирать внутреннюю development-ветку из старых инструкций. Обычный `git clone` должен давать текущую публичную линию проекта.

### Базовая установка

```bash
sudo ./packaging/install.sh --generate-admin-password
```

### Appliance с локальным kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` устанавливает минимальный display stack: Chromium и Cage либо Xorg/xinit. GNOME/KDE/XFCE не требуются. На Raspberry Pi OS дополнительный desktop environment устанавливать не нужно.

Обычная appliance-установка слушает `0.0.0.0:8000`. Локальный kiosk открывает `http://127.0.0.1:8000/`.

Если нужен только loopback:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

## Что делает installer

`packaging/install.sh` идемпотентно выполняет:

1. определяет distro family, package manager и архитектуру;
2. устанавливает обязательные пакеты и доступные optional providers;
3. создаёт или переиспользует непривилегированный account `wirescope`;
4. создаёт data/runtime/evidence directories;
5. обеспечивает наличие группы `wireshark` на чистых Debian/Raspberry Pi OS системах;
6. настраивает packet-capture privileges только для `/usr/bin/dumpcap`;
7. создаёт `.venv` и устанавливает Python dependencies;
8. записывает `/etc/wirescope/wirescope.env`;
9. устанавливает systemd units для API/worker и optional kiosk;
10. применяет Alembic migrations;
11. создаёт первого `auditor` без встроенного default password;
12. запускает сервисы, если не указан `--no-start`.

Generic kiosk dependency set не должен содержать VMware-only пакеты. VMware-specific Xorg integration не является зависимостью Raspberry Pi/ARM64 установки.

## Сервисы

System install использует:

```text
wirescope-api.service
wirescope-worker.service
[wirescope-kiosk.service]
```

API и worker работают без root.

Packet capture privileges остаются только у `dumpcap`:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 capabilities: cap_net_admin,cap_net_raw=eip
```

Проверка:

```bash
sudo /opt/wirescope/.venv/bin/python -m appliance verify \
  --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

## Первый вход

При `--generate-admin-password` первоначальный пароль сохраняется в защищённый файл:

```text
/etc/wirescope/initial-admin.txt
```

Username по умолчанию:

```text
auditor
```

Проверить пароль:

```bash
sudo cat /etc/wirescope/initial-admin.txt
```

После сохранения пароля в password manager файл можно удалить.

## Проверка после установки

```bash
systemctl is-active wirescope-api
systemctl is-active wirescope-worker
systemctl is-active wirescope-kiosk 2>/dev/null || true

curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

Ожидается:

- `/health` → API жив;
- `/ready` → database, migrations, worker, `dumpcap`, `tshark` готовы;
- `/capabilities` → доступность optional providers.

## Raspberry Pi OS

Рекомендуется 64-bit Raspberry Pi OS Lite. Полный desktop не требуется.

Типовой appliance layout:

- `wlan0` — management/Web UI;
- `eth0` — audited network;
- kiosk — локальный Chromium на дисплее устройства.

WireScope не требует Raspberry Pi OS как единственную платформу, но Pi OS является удобной базой для Raspberry Pi hardware/display ecosystem.

## TLS / reverse proxy

Для loopback + reverse proxy:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --trust-proxy
```

Шаблоны Caddy/nginx находятся в `packaging/proxy/` и при system install копируются в `/etc/wirescope/proxy/`. Installer не запускает reverse proxy и не меняет firewall автоматически.

Direct TLS:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

## User install

Для user-systemd установка может выполняться из home checkout:

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password
```

Используются:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

## Основные флаги

```text
--dry-run                 показать план без изменений
--skip-packages           не запускать package manager
--skip-pip                переиспользовать текущий venv
--no-start                не стартовать units
--no-optional-providers   только базовые зависимости
--with-kiosk              установить минимальный kiosk stack
--enable-kiosk            включить system kiosk на tty1
--user-kiosk              user-session kiosk
--user-install            user systemd install
--bind-host               bind API; appliance default 0.0.0.0
--bind-port               порт API; default 8000
--trust-proxy             reverse-proxy mode
--tls-cert / --tls-key    direct TLS
--overwrite-env           переписать wirescope.env
```

## Обновление

Проверьте состояние checkout:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
git fetch --tags origin
```

Перед существенным обновлением сделайте backup:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Затем:

```bash
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

После upgrade:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/ready
```

Для production/reproducible deployment фиксируйте release/tag/commit SHA, а не случайный промежуточный development revision.

## Диагностика установки

Если installer сообщает, что systemd service не стартовал, сначала смотрите реальную причину в journal:

```bash
sudo journalctl -u wirescope-api.service -b -n 120 --no-pager
sudo journalctl -u wirescope-worker.service -b -n 120 --no-pager
sudo journalctl -u wirescope-kiosk.service -b -n 120 --no-pager
```

Не переносите уже созданный `.venv` между разными путями. Если checkout действительно был перемещён после создания venv, удалите только `.venv` и создайте его заново installer'ом.
