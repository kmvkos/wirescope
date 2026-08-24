# Установка WireScope

**Русский** · [English](en/INSTALLATION.md)

WireScope ставится на обычный Linux-хост или ВМ. Поддерживаемые семейства:

- Debian / Ubuntu;
- Fedora / RHEL / Rocky;
- openSUSE / SLES;
- `amd64` и `arm64`.

Raspberry Pi подходит как железо, но отдельной Raspberry Pi OS проект не требует.

## Перед установкой

WireScope можно использовать двумя способами:

1. **автономный киоск** — монитор подключён к самому устройству, Chromium открывает локальный интерфейс;
2. **удалённый браузер** — оператор заходит с другого ПК через HTTPS/reverse proxy.

Оба режима используют один и тот же backend и worker.

Для system install рекомендуемый layout:

```text
/opt/wirescope                  Git checkout + .venv
/etc/wirescope                  конфигурация
/var/lib/wirescope              SQLite, runtime, evidence, backups
/etc/systemd/system             systemd units
```

Установщик **не копирует исходники** из checkout в `/opt/wirescope`. Он запускается из того каталога, где находится проект, и systemd units потом ссылаются на этот checkout. После установки его нельзя просто удалить или переименовать.

## Получение исходников

### SSH

Если SSH-ключ лежит у обычного пользователя, клонируйте без `sudo`:

```bash
git clone git@github.com:kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

`sudo git clone ...` использовал бы SSH-ключи root, а не текущего пользователя.

Если у root уже настроен доступ к GitHub, можно клонировать сразу:

```bash
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

### HTTPS

```bash
git clone https://github.com/kmvkos/wirescope.git
sudo mv wirescope /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance
```

Для приватного репозитория GitHub нужен токен/credential helper; пароль аккаунта вместо токена не используется.

## Самый простой system install

Для автономного устройства с локальным экраном:

```bash
cd /opt/wirescope
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

После установки:

```bash
sudo reboot
```

При загрузке `wirescope-kiosk` занимает `tty1` и открывает Chromium на:

```text
http://127.0.0.1:8000/
```

Полноценный desktop environment для этого не нужен.

### Почему `--bind-host 127.0.0.1` передаётся явно

В `config/settings.py` application default — `127.0.0.1`, но CLI appliance installer сейчас имеет собственный default `--bind-host 0.0.0.0`.

Поэтому для киоска и reverse-proxy схемы в документации bind всегда задаётся явно:

```bash
--bind-host 127.0.0.1
```

Открытый HTTP на `0.0.0.0:8000` допустим только как осознанный lab/management вариант с firewall. Для обычной LAN-эксплуатации предпочтительнее HTTPS через Caddy/nginx.

## Что делает installer

`packaging/install.sh` в итоге вызывает `python -m appliance install`.

В system install он:

1. определяет дистрибутив, package manager и архитектуру;
2. ставит системные зависимости через `apt`, `dnf`, `yum` или `zypper`;
3. создаёт или переиспользует непривилегированного пользователя `wirescope`;
4. создаёт каталоги данных;
5. настраивает `dumpcap` через группу `wireshark` и file capabilities;
6. создаёт `.venv` и ставит pinned Python dependencies;
7. пишет `/etc/wirescope/wirescope.env`;
8. устанавливает `wirescope-api` и `wirescope-worker` systemd units;
9. применяет Alembic migrations;
10. создаёт первого пользователя GUI;
11. запускает службы;
12. при `--with-kiosk` ставит минимальный browser/display stack;
13. при `--enable-kiosk` включает kiosk unit на `tty1`.

Повторный запуск installer рассчитан на upgrade/idempotent setup, а не на «чистую установку с нуля каждый раз».

## Первый пользователь

В WireScope нет встроенного пароля по умолчанию.

Самый удобный вариант:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Сгенерированный пароль записывается в:

```text
/etc/wirescope/initial-admin.txt
```

Файл имеет mode `0600`. После того как пароль сохранён в password manager, файл лучше удалить.

Имя пользователя по умолчанию:

```text
auditor
```

Можно передать собственный файл с паролем:

```bash
sudo ./packaging/install.sh \
  --auditor-password-file /root/auditor.pass \
  --bind-host 127.0.0.1
```

Файл должен быть `0600` или строже.

Если доступ к GUI потерян, пароль можно сбросить через CLI:

```bash
/opt/wirescope/.venv/bin/python -m appliance set-password auditor
```

Для обычной смены пароля использовать CLI не нужно: после входа в GUI есть **«Сменить пароль»**.

## Локальный kiosk

WireScope не ставит GNOME, KDE, XFCE, GDM или LightDM.

Минимальная схема:

```text
multi-user.target
    ├── wirescope-api
    ├── wirescope-worker
    └── wirescope-kiosk
             ↓
           tty1
             ↓
      Cage или Xorg/xinit
             ↓
          Chromium
             ↓
  http://127.0.0.1:8000/
```

Установка:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk \
  --enable-kiosk
```

Если пакеты уже стоят и нужно только включить kiosk:

```bash
sudo ./packaging/install.sh --skip-packages --enable-kiosk
```

или:

```bash
sudo systemctl enable --now wirescope-kiosk
```

### VMware

На VMware WireScope использует Xorg/xinit, а не Cage. Installer при необходимости добавляет VMware Xorg driver/input packages и `open-vm-tools`.

После установки перезагрузите ВМ **с подключённой консолью**. SSH продолжит работать: kiosk занимает локальный `tty1`, а не отключает сеть или sshd.

Если консоль чёрная и нет ни Chromium, ни login prompt:

```bash
sudo systemctl start getty@tty1
sudo systemctl status wirescope-kiosk
sudo journalctl -u wirescope-kiosk -e
```

`OnFailure` kiosk-unit также рассчитан на возврат текстового login на `tty1`.

## Удалённый браузер через HTTPS

Рекомендуемая схема для LAN:

```text
browser
   │ HTTPS :443
   ▼
Caddy / nginx
   │ HTTP loopback
   ▼
127.0.0.1:8000
   │
WireScope API
```

Установить WireScope:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --trust-proxy \
  --bind-host 127.0.0.1
```

`--trust-proxy` включает режим для reverse proxy: session cookie становится `Secure`, а forwarded headers принимаются только от loopback proxy.

Примеры конфигов находятся в:

```text
packaging/proxy/
```

После установки копии также могут лежать в:

```text
/etc/wirescope/proxy/
```

Подробности: [packaging/proxy/README.md](../packaging/proxy/README.md).

Installer сам **не запускает Caddy/nginx и не переписывает firewall**.

Снаружи публикуйте 443, а не 8000.

### Self-signed TLS для лаборатории

```bash
sudo python3 -m appliance tls-selfsigned \
  --output-dir /etc/wirescope/tls \
  --common-name wirescope.example
```

Для production предпочтительнее нормальный сертификат: Caddy automatic HTTPS или certbot/nginx.

### Прямой TLS через Uvicorn

Поддерживается и прямой TLS без reverse proxy:

```bash
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

Тогда URL:

```text
https://<host>:8443/
```

Пути к cert/key хранятся в environment file; PEM содержимое не должно попадать в systemd units.

## User-systemd install

Если system services не нужны или нет постоянного root-доступа:

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Пути становятся пользовательскими:

```text
~/.local/share/wirescope
~/.config/wirescope
~/.config/systemd/user
```

Управление:

```bash
systemctl --user status wirescope-api wirescope-worker
systemctl --user restart wirescope-api wirescope-worker
journalctl --user -u wirescope-api -u wirescope-worker -e
```

`--user-install` не ставит OS packages. `dumpcap` всё равно один раз должен быть настроен от root.

User unit не может использовать `SupplementaryGroups=` как system unit. Поэтому WireScope запускает API/worker через `sg wireshark`, чтобы актуальная группа `wireshark` работала без logout/login.

При необходимости автозапуска user manager:

```bash
sudo loginctl enable-linger "$USER"
```

## Дистрибутивы

### Debian / Ubuntu

Основные пакеты захвата:

- `tshark`;
- `wireshark-common` (`dumpcap`);
- `libcap2-bin`.

Установка:

```bash
sudo apt-get update
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### Fedora / RHEL / Rocky

Installer выбирает `dnf`, а если его нет — `yum`.

Основной Wireshark CLI package:

```text
wireshark-cli
```

Пример:

```bash
sudo dnf -y install python3
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### openSUSE / SLES

Installer использует `zypper`.

Capture package — обычно `wireshark-cli`, fallback — `wireshark`. `setcap` приходит из `libcap-progs`.

```bash
sudo zypper --non-interactive install python3
sudo ./packaging/install.sh \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

### Основные различия пакетов

| Назначение | Debian / Ubuntu | Fedora / RHEL | openSUSE |
| --- | --- | --- | --- |
| Package manager | `apt-get` | `dnf` / `yum` | `zypper` |
| dumpcap/tshark | `wireshark-common`, `tshark` | `wireshark-cli` | `wireshark-cli` / `wireshark` |
| `setcap` | `libcap2-bin` | `libcap` | `libcap-progs` |
| Python headers | `python3-dev` | `python3-devel` | `python3-devel` |
| iproute | `iproute2` | `iproute` | `iproute2` |
| sqlite CLI | `sqlite3` | `sqlite` | `sqlite3` |
| DNS tools | `bind9-dnsutils` | `bind-utils` | `bind-utils` |

## Полезные installer flags

```text
--dry-run
--skip-packages
--skip-apt                 alias для --skip-packages
--skip-pip
--no-start
--no-optional-providers
--with-kiosk
--enable-kiosk
--user-kiosk
--user-install
--generate-admin-password
--auditor-password-file PATH
--overwrite-env
--bind-host HOST
--bind-port PORT
--trust-proxy
--tls-cert PATH
--tls-key PATH
```

`--user-kiosk` относится к уже существующей graphical user session. Для обычного appliance без desktop используйте system `--enable-kiosk`.

## Проверка после установки

```bash
sudo systemctl status wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
sudo python3 -m appliance verify --project-root /opt/wirescope
```

`/api/health` говорит, что API жив.

`/api/ready` дополнительно проверяет:

- доступность SQLite;
- актуальность Alembic revision;
- heartbeat worker;
- наличие обязательных binaries (`dumpcap`, `tshark`, `nmap`).

## Проверка прав `dumpcap`

Ожидаемая system-install схема:

```text
/usr/bin/dumpcap
owner: root
 group: wireshark
 mode: 0750
 caps: cap_net_admin,cap_net_raw=eip
```

Проверка:

```bash
getent group wireshark
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

На Python interpreter capabilities быть не должно.

API и worker не запускаются как root.

## Runtime paths

System install environment обычно задаёт:

```bash
WIRESCOPE_DATA_DIR=/var/lib/wirescope
WIRESCOPE_DATABASE_PATH=/var/lib/wirescope/wirescope.db
WIRESCOPE_EVIDENCE_DIR=/var/lib/wirescope/evidence
WIRESCOPE_RUNTIME_DIR=/var/lib/wirescope/runtime
WIRESCOPE_CAPTURE_DIR=/var/lib/wirescope/runtime/captures
WIRESCOPE_BIND_HOST=127.0.0.1
WIRESCOPE_BIND_PORT=8000
WIRESCOPE_DOCS_ENABLED=false
```

Environment file:

```text
/etc/wirescope/wirescope.env
```

Не размещайте рабочую SQLite на NFS. Нужна локальная файловая система с нормальной locking semantics.

## Миграции

Installer применяет Alembic автоматически.

Вручную:

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

WireScope не создаёт production tables через `Base.metadata.create_all()`.

## Upgrade

Перед существенным обновлением сначала backup:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Затем:

```bash
cd /opt/wirescope
git pull
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Если системные пакеты уже проверены и менять их не нужно:

```bash
sudo ./packaging/upgrade.sh \
  --project-root /opt/wirescope \
  --skip-packages
```

После обновления:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

## Rollback

Нормальный rollback строится вокруг backup, а не вокруг слепого `alembic downgrade`.

1. Остановить API и worker.
2. Восстановить pre-upgrade backup SQLite/evidence.
3. Checkout предыдущего known-good Git revision.
4. Переустановить проект в `.venv`.
5. Запустить worker и API.
6. Проверить `/api/ready` и вход в GUI.

Пример:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

cd /opt/wirescope
git checkout <known-good-commit>
/opt/wirescope/.venv/bin/pip install -e /opt/wirescope

sudo systemctl start wirescope-worker wirescope-api
```

Alembic migrations в обычной эксплуатации считаются forward-only, если downgrade конкретной revision отдельно не был протестирован.

## Backup / restore

Backup:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

По умолчанию архив создаётся под:

```text
/var/lib/wirescope/backups/<UTC timestamp>/
```

Restore выполнять при остановленных службах:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

sudo systemctl start wirescope-worker wirescope-api
```

## Что происходит при аварийном reboot

SQLite работает с WAL, foreign keys, короткими транзакциями и `synchronous=FULL` по умолчанию. Evidence записывается через temporary file + atomic rename.

После старта worker:

- `queued` jobs остаются в очереди;
- jobs, которые были `running`, становятся `interrupted` с `application_restart`;
- автоматического retry нет;
- stale locks и временные файлы чистятся контролируемой startup maintenance.

Перезапуск браузера или kiosk к job lifecycle отношения не имеет.

## Release checksums

```bash
python3 -m appliance checksums \
  --project-root /opt/wirescope \
  --output /opt/wirescope/packaging/SHA256SUMS

sha256sum -c /opt/wirescope/packaging/SHA256SUMS
```

При распространении release artifacts `SHA256SUMS` можно подписывать отдельным operator GPG key. Installer приватный ключ не хранит.

## Дальше

- [Архитектура](ARCHITECTURE.md)
- [Модель безопасности](SECURITY_MODEL.md)
- [Runbook](RUNBOOK.md)
- [Разработка](DEVELOPMENT.md)
