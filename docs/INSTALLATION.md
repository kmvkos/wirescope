# Установка WireScope

[English](en/INSTALLATION.md)

WireScope устанавливается как отдельный Linux appliance или как приложение на уже существующую ВМ/сервер. Поддерживаются Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`. Raspberry Pi подходит как аппаратная платформа, но не является обязательным условием.

Установщик работает **из Git checkout**. Код обычно находится в `/opt/wirescope`, изменяемые данные — в `/var/lib/wirescope`, конфигурация — в `/etc/wirescope`.

## Рекомендуемая установка

Репозиторий приватный, поэтому нужен SSH key или GitHub token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance
cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Клон лучше делать без `sudo`: иначе Git использует ключи root. Checkout также выполняется до переноса в `/opt`, чтобы не создавать лишних проблем с ownership и `safe.directory`.

Базовая system install:

```bash
sudo ./packaging/install.sh --generate-admin-password
```

По умолчанию API слушает **`127.0.0.1:8000`**. Это безопасный вариант для локального браузера, kiosk и reverse proxy.

### Локальный kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` устанавливает минимальный display stack: Chromium и Cage либо Xorg/xinit. Полный GNOME/KDE/XFCE не нужен. На VMware используется Xorg path.

Системный kiosk запускается на `tty1` после boot и открывает `http://127.0.0.1:8000/`. Перезапуск kiosk/Chromium не останавливает API, worker или уже выполняющийся audit.

### Доступ с другой машины

Предпочтительная схема:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Установите WireScope на loopback с trust proxy:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --trust-proxy
```

Примеры Caddy/nginx и firewall находятся в `packaging/proxy/` и после system install копируются в `/etc/wirescope/proxy/`. Установщик сам не включает reverse proxy и не переписывает firewall хоста.

### Прямой bind на LAN

Если reverse proxy действительно не нужен, bind можно открыть явно:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0
```

Обычный HTTP на `0.0.0.0:8000` не считается рекомендуемой production-схемой. Ограничьте доступ firewall или используйте direct TLS.

Direct TLS:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

PEM содержимое не записывается в systemd unit; там используются только пути из environment file.

## Что делает installer

`packaging/install.sh` вызывает `python -m appliance install` и выполняет идемпотентную настройку:

1. определяет distro family, package manager и архитектуру;
2. устанавливает обязательные пакеты и доступные optional providers;
3. создаёт или переиспользует unprivileged пользователя `wirescope`;
4. создаёт data/runtime/evidence directories;
5. настраивает capabilities только для `dumpcap`;
6. создаёт `.venv` и устанавливает pinned Python dependencies;
7. записывает `/etc/wirescope/wirescope.env`;
8. устанавливает systemd units API/worker и, при необходимости, kiosk;
9. применяет Alembic migrations;
10. создаёт первого auditor без встроенного default password;
11. запускает службы, если не указан `--no-start`.

Nuclei и Nikto installer по умолчанию не устанавливает.

## Основные пути

System install:

```text
/opt/wirescope
    Git checkout + .venv

/etc/wirescope/
    wirescope.env
    proxy/
    initial-admin.txt   # только после generated password, удалить после сохранения

/var/lib/wirescope/
    wirescope.db
    evidence/
    runtime/
    backups/
```

User install использует `~/.local/share/wirescope`, `~/.config/wirescope` и `~/.config/systemd/user`.

## Сервисная модель

Production system install запускает:

```text
wirescope-worker.service
wirescope-api.service
[wirescope-kiosk.service]
```

API и worker работают от unprivileged account. Для system units membership в `wireshark` задаётся через `SupplementaryGroups=wireshark`.

User units не могут использовать этот systemd directive так же, поэтому installer запускает процессы через `sg wireshark`, чтобы обновлённая group membership начала работать без обязательного logout.

## Packet capture privileges

Правильное состояние:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 capabilities: cap_net_admin,cap_net_raw=eip
```

Python/uvicorn таких capabilities получать не должны.

Проверка:

```bash
sudo /opt/wirescope/.venv/bin/python -m appliance verify \
  --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

## Первый вход

При `--generate-admin-password` пароль записывается в защищённый файл, обычно `/etc/wirescope/initial-admin.txt`. Скопируйте пароль в password manager и удалите файл.

GUI user по умолчанию — `auditor`. Встроенного постоянного пароля нет.

Сброс при потере доступа:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

## Проверка после установки

```bash
systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/ready
```

`/api/v1` — канонический API. `/api` пока остаётся compatibility alias для текущего GUI и клиентов.

`/api/health` проверяет жив ли API. `/api/ready` дополнительно требует доступную БД, актуальные migrations, worker heartbeat и обязательные binaries.

## Debian / Ubuntu

Установщик использует `apt`. Основные пакеты включают Python, `iproute2`, `tshark`, `wireshark-common`/`dumpcap`, SQLite и `libcap2-bin`.

```bash
sudo ./packaging/install.sh --generate-admin-password
```

Для kiosk добавьте `--with-kiosk --enable-kiosk`.

## Fedora / RHEL / Rocky

Используется `dnf`, либо `yum`, если `dnf` отсутствует. `dumpcap` и `tshark` приходят из `wireshark-cli`.

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh --generate-admin-password
```

## openSUSE / SLES

Используется `zypper`; capture package — `wireshark-cli` или distro fallback.

```bash
sudo zypper --non-interactive install python3
sudo ./packaging/install.sh --generate-admin-password
```

## User install

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password
```

OS packages и initial `dumpcap` capability setup всё равно требуют административной настройки хотя бы один раз.

## Полезные флаги

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
--bind-host               адрес API; default 127.0.0.1
--bind-port               порт API; default 8000
--trust-proxy             режим reverse proxy
--tls-cert / --tls-key    direct TLS
--overwrite-env           переписать существующий wirescope.env
```

## Обновление уже установленной ВМ

Если checkout уже находится в `/opt/wirescope`, код обновляется обычным Git workflow.

Перед обновлением:

```bash
cd /opt/wirescope
git status
git branch --show-current
git fetch origin
```

Если рабочее дерево чистое и нужна текущая ветка:

```bash
git pull --ff-only
```

После code-only update без новых migrations/dependencies обычно достаточно:

```bash
sudo systemctl restart wirescope-worker wirescope-api
curl -sS http://127.0.0.1:8000/api/ready
```

Для общего upgrade path используйте:

```bash
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Upgrade повторно проверяет environment, venv, dumpcap и запускает migrations.

## Backup перед существенным upgrade

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Backups сохраняются в `/var/lib/wirescope/backups/`.

## Rollback

1. остановить API и worker;
2. восстановить pre-upgrade backup, если менялась схема/data format;
3. вернуть предыдущий известный Git revision;
4. при необходимости переустановить editable package в `.venv`;
5. запустить worker и API;
6. проверить `/api/ready`.

В нормальной эксплуатации Alembic считается forward migration mechanism; случайный `alembic downgrade` не заменяет восстановление backup.

## Power loss и restart

SQLite работает с WAL и короткими транзакциями. Evidence записывается атомарно.

После worker restart:

- `running` jobs становятся `interrupted` с `application_restart`;
- `queued` остаются queued;
- автоматического retry нет;
- stale temporary files и locks очищаются консервативно.

Перезапуск браузера или kiosk не меняет состояние jobs.
