# Установка WireScope

[English](en/INSTALLATION.md)

WireScope можно поставить на отдельный Linux appliance, ВМ или существующий сервер. Поддерживаются Debian/Ubuntu, Fedora/RHEL/Rocky и openSUSE на `amd64` и `arm64`. Raspberry Pi подходит как аппаратная платформа, но не является обязательным.

Установщик работает **из Git checkout**. Для system install рекомендуемый layout такой:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

## Клонирование

Репозиторий приватный, поэтому нужен SSH key или GitHub token.

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git fetch --tags origin

# Для воспроизводимой установки выберите нужный release/tag/checkpoint:
# git checkout <release-or-checkpoint>

cd ..
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
```

Не используйте имя старой milestone-ветки, скопированное из исторической инструкции. Для production-like deployment лучше фиксировать конкретный release/tag/checkpoint и записывать его SHA.

Клон лучше делать без `sudo`: иначе Git использует SSH-конфигурацию root. Checkout выполняется до переноса в `/opt`, чтобы не создавать лишних проблем с ownership и `safe.directory`.

## Базовая system install

```bash
sudo ./packaging/install.sh --generate-admin-password
```

Обычная appliance-установка слушает **`0.0.0.0:8000`**. Это намеренная модель WireScope: UI должен быть доступен через любой настроенный интерфейс устройства — Ethernet, Wi‑Fi и т.д.

Локальный браузер при этом может открывать:

```text
http://127.0.0.1:8000/
```

а другой компьютер — адрес конкретного интерфейса:

```text
http://<ip-wirescope>:8000/
```

Если в конкретном развёртывании нужен только loopback, это задаётся явно:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Firewall, TLS и reverse proxy остаются доступными вариантами ужесточения доступа, но не являются обязательным условием работы WireScope.

## Локальный kiosk

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --with-kiosk \
  --enable-kiosk
```

`--with-kiosk` ставит минимальный display stack: Chromium и Cage либо Xorg/xinit. Полный GNOME/KDE/XFCE не требуется. На VMware используется Xorg path.

После boot системный kiosk занимает `tty1` и открывает `http://127.0.0.1:8000/`. Перезапуск Chromium не останавливает API, worker или выполняющийся audit.

## TLS / reverse proxy — по необходимости

Если WireScope работает в сети, где обычный HTTP нежелателен, можно оставить приложение на loopback и поставить Caddy/nginx:

```text
browser → HTTPS 443 → Caddy/nginx → 127.0.0.1:8000
```

Пример установки:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --trust-proxy
```

Шаблоны находятся в `packaging/proxy/` и при system install копируются в `/etc/wirescope/proxy/`. Installer не запускает Caddy/nginx автоматически и не меняет firewall хоста.

Direct TLS тоже поддерживается:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

В environment/systemd попадают пути к сертификату и ключу, а не PEM-содержимое.

## Что делает installer

`packaging/install.sh` вызывает appliance installer и идемпотентно выполняет:

1. определение distro family, package manager и архитектуры;
2. установку обязательных пакетов и доступных optional providers;
3. создание или переиспользование unprivileged account `wirescope`;
4. создание data/runtime/evidence directories;
5. настройку privileges только для `dumpcap`;
6. создание `.venv` и установку pinned Python dependencies;
7. запись `/etc/wirescope/wirescope.env`;
8. установку systemd units для API/worker и optional kiosk;
9. Alembic migrations;
10. создание первого `auditor` без встроенного default password;
11. запуск сервисов, если не указан `--no-start`.

Nuclei и Nikto по умолчанию не устанавливаются. Optional topology management providers включают Net-SNMP tools и OpenSSH client; их отсутствие не делает базовый appliance `not_ready`.

## Сервисы

Обычный system install запускает:

```text
wirescope-api.service
wirescope-worker.service
[wirescope-kiosk.service]
```

API и worker работают от непривилегированного пользователя.

Packet capture privileges должны оставаться только у `dumpcap`:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 capabilities: cap_net_admin,cap_net_raw=eip
```

Python и uvicorn этих capabilities получать не должны.

Проверка:

```bash
sudo /opt/wirescope/.venv/bin/python -m appliance verify \
  --project-root /opt/wirescope
sudo -u wirescope /usr/bin/dumpcap -D
```

## Первый вход

При `--generate-admin-password` installer создаёт защищённый файл с первоначальным паролем, обычно:

```text
/etc/wirescope/initial-admin.txt
```

Username по умолчанию — `auditor`. Постоянного встроенного пароля нет. После сохранения пароля в password manager файл лучше удалить.

Сброс пароля:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

## Проверка после установки

```bash
systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

С другого компьютера подставьте IP WireScope вместо `127.0.0.1`.

`/health` показывает, что API жив. `/ready` проверяет SQLite, migrations, worker, `dumpcap` и `tshark`. Необязательные providers показываются через `/capabilities` и не делают весь appliance `not_ready`.

## Дистрибутивы

### Debian / Ubuntu

Installer использует `apt`. В базовый набор входят Python, `iproute2`, `tshark`/Wireshark CLI, SQLite и `libcap2-bin`.

```bash
sudo ./packaging/install.sh --generate-admin-password
```

### Fedora / RHEL / Rocky

Используется `dnf`, либо `yum` fallback. `dumpcap`/`tshark` обычно приходят из `wireshark-cli`.

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh --generate-admin-password
```

### openSUSE / SLES

Используется `zypper` и distro package для Wireshark CLI.

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

User install использует:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

OS packages и первоначальная настройка `dumpcap` всё равно могут потребовать root один раз.

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
--trust-proxy             режим reverse proxy
--tls-cert / --tls-key    direct TLS
--overwrite-env           переписать wirescope.env
```

## Обновление установленной ВМ

Если checkout уже находится в `/opt/wirescope`, сначала убедитесь, что рабочее дерево чистое:

```bash
cd /opt/wirescope
git status --short
git branch --show-current
git rev-parse HEAD
git fetch --tags origin
```

Для воспроизводимого upgrade переключайтесь на конкретный проверенный ref:

```bash
git checkout <release-tag-or-checkpoint>
git rev-parse HEAD
```

Перед существенным обновлением сделайте backup, затем используйте полный upgrade path:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup

sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

После upgrade:

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/v1/ready
curl -sS http://127.0.0.1:8000/api/v1/capabilities
```

Не используйте `git pull` как замену выбору release/checkpoint, если appliance должен оставаться на воспроизводимом revision.

Upgrade использует appliance default `0.0.0.0`, если явно не передан другой `--bind-host`.

## Backup и rollback

Перед существенным upgrade backup уже должен быть создан командой выше.

При rollback:

1. остановить API и worker;
2. восстановить backup, если менялась schema/data format;
3. вернуть предыдущий проверенный Git revision;
4. при необходимости переустановить package в `.venv`;
5. запустить worker и API;
6. проверить `/api/v1/ready`.

## Restart / power loss

SQLite работает в WAL mode с короткими транзакциями, evidence записывается атомарно.

После worker restart:

- `running` jobs становятся `interrupted` с `application_restart`;
- `queued` остаются queued;
- автоматического retry нет;
- stale locks/temp files очищаются консервативно.

Перезапуск браузера или kiosk не меняет состояние jobs.