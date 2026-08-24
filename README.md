# WireScope

Переносной самодостаточный **сетевой аудитор** для обычного Linux
(Debian/Ubuntu, Fedora/RHEL/Rocky, openSUSE; amd64 или arm64).
Raspberry Pi не обязателен, Raspberry Pi OS не требуется.

WireScope ставится на отдельный хост или ВМ и проводит аудит локальной сети
по шагам:

1. пассивный захват и разбор трафика;
2. подтверждённый оператором локальный scope (не вся сеть);
3. активное обнаружение только внутри этого scope;
4. протокольные проверки по инвентарю;
5. находки (findings);
6. HTML-отчёт и итоговая сводка (executive summary).

Интерфейс оператора — **на русском**. Отдельный рабочий стол (GNOME, XFCE,
KDE, GDM, LightDM) не нужен: после загрузки киоск занимает **tty1** и открывает
Chromium на `http://127.0.0.1:8000/`.

## Два режима работы

Оба режима равноценны. Адрес на интерфейсе захвата может отсутствовать
(без IP и без DHCP) — GUI всё равно открывается локально.

| Режим | Как открыть GUI |
| --- | --- |
| **Локальный киоск** | Дисплей этого компьютера, `http://127.0.0.1:8000/`. Сеть до вашего ПК не нужна. |
| **Браузер с другого ПК** | Предпочтительно HTTPS через Caddy/nginx (`--trust-proxy`), API остаётся на loopback. |

## Кто входит куда

Это **разные** учётки:

- **Linux-пользователь `wirescope`** — учётная запись ОС для установки,
  `sudo` и администрирования служб. Пароль `sudo` — пароль этого пользователя,
  не пароль GUI.
- **GUI-пользователь `auditor`** — вход в веб-интерфейс WireScope (киоск или
  браузер). В Linux как `auditor` не логиньтесь.

Встроенного пароля по умолчанию нет. Первый аудитор создаётся установщиком,
когда таблица пользователей пуста. Сгенерированный пароль записывается в
файл с правами `0600` (только root); скопируйте его в менеджер паролей и
удалите файл. Содержимое этого файла и реальные пароли в репозиторий не
попадают.

## Установка

Репозиторий на GitHub **приватный**:
[`https://github.com/kmvkos/wirescope`](https://github.com/kmvkos/wirescope).
Нужен SSH-ключ или учётные данные HTTPS.

Установщик **работает из клона** (venv, frontend, скрипты киоска). Дерево
в `/opt/wirescope` само не копируется. Данные — `/var/lib/wirescope`,
конфиг — `/etc/wirescope`. `--project-root` по умолчанию — каталог, в
котором лежит `packaging/` (корень клона).

### Клон в `/opt/wirescope` (рекомендуемый layout)

```bash
sudo git clone git@github.com:kmvkos/wirescope.git /opt/wirescope
cd /opt/wirescope
sudo git checkout milestone-8-appliance   # или main, если он достаточно свежий
sudo ./packaging/install.sh --with-kiosk --enable-kiosk
```

`sudo git clone` использует **ключи root**. Если ключ у вашего пользователя,
клонируйте без `sudo`, затем `sudo mv wirescope /opt/wirescope`, либо
ставьте из другого каталога с `--project-root` (ниже).

### Клон куда угодно

```bash
git clone git@github.com:kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance   # или main, если он достаточно свежий
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Службы остаются в этом клоне: не переименовывайте и не удаляйте его после
установки.

### HTTPS

```bash
git clone https://github.com/kmvkos/wirescope.git
cd wirescope
git checkout milestone-8-appliance   # или main, если он достаточно свежий
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Приватный репозиторий: GitHub запросит логин и токен (не пароль аккаунта)
или сохранённые credentials.

### Киоск на tty1

`--with-kiosk` ставит минимальный стек (Cage или Xorg/`xinit` и Chromium),
**не** GNOME/XFCE. `--enable-kiosk` включает системный юнит на
`multi-user.target`.

Из любого клона:

```bash
sudo ./packaging/install.sh \
  --project-root "$PWD" \
  --generate-admin-password \
  --bind-host 127.0.0.1 \
  --with-kiosk --enable-kiosk
```

Если пакеты уже стоят:

```bash
sudo ./packaging/install.sh --skip-packages --enable-kiosk
# или
sudo systemctl enable --now wirescope-kiosk
```

После успеха перезагрузите машину с подключённой **консолью** (не только SSH).
На tty1 откроется Chromium; в GUI войдите как `auditor`. SSH для админки
продолжает работать — киоск занимает только локальный экран.

### `--user-install`

Если нет passwordless root, можно поставить в user systemd
(права на `dumpcap` всё равно нужны один раз от root):

```bash
./packaging/install.sh \
  --user-install \
  --generate-admin-password \
  --bind-host 127.0.0.1
```

Данные по умолчанию: `~/.local/share/wirescope`, конфиг
`~/.config/wirescope`, юниты `~/.config/systemd/user`.
Управление: `systemctl --user`. `--user-install` не ставит пакеты ОС;
Chromium и Cage/`xinit` поставьте заранее (`--with-kiosk` от root или
пакеты дистрибутива).

`--bind-host` задаёт адрес API. По умолчанию `127.0.0.1:8000` — только
локальный браузер/киоск. Для доступа с другого ПК держите API на loopback
и терминируйте TLS на Caddy/nginx (`--trust-proxy`). Голые HTTP на
`0.0.0.0:8000` — небезопасный вариант для LAN.

### VMware

На VMware киоск запускает **Xorg**, а не Cage (Cage на VMware зависает
на чёрном экране). Установщик подтягивает `xserver-xorg-video-vmware`,
ввод и `open-vm-tools`.

Если консоль VMware **чёрная** (нет login и нет Chromium): киоск занял tty1
и не смог открыть экран. По SSH:

```bash
sudo systemctl start getty@tty1
```

На консоли должен появиться login. Затем
`sudo systemctl status wirescope-kiosk` и журнал юнита.

Подробности: [установка](docs/INSTALLATION.md),
[модель безопасности](docs/SECURITY_MODEL.md),
[операционный runbook](docs/RUNBOOK.md).

## Scope и привилегии

- Активное сканирование и протокольные проверки идут **только** по
  подтверждённому оператором локальному scope. `0.0.0.0/0`, `::/0` и
  multicast отклоняются.
- Backend (API и worker) **не** запускается от root.
- Права захвата пакетов есть только у `/usr/bin/dumpcap`
  (`CAP_NET_RAW` / `CAP_NET_ADMIN`, группа `wireshark`). Процесс Python
  этих capabilities не получает.

## Тесты

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -m "not network"
```

Маркер `network` — опциональные тесты, которые могут трогать живую сеть.
По умолчанию pytest и так пропускает `network` и `live_pi`.
Raspberry Pi OS Lite-тесты (`pytest -m live_pi`) на обычном Linux не нужны.

## Состав

- `backend/` — FastAPI и HTTP API
- `engine/` — окружение, пассивный захват, оценка
- `jobs/` — долговечные задания и worker
- `inventory/` — подтверждённый scope, активы, сервисы
- `protocol_audits/` — проверки протоколов по инвентарю
- `findings/` — правила находок
- `reports/` — HTML/JSON-отчёт и итоговая сводка
- `frontend/` — GUI на русском
- `auth/` — локальные пользователи и сессии
- `packaging/` / `appliance/` — установщик, systemd, киоск, backup
- `docs/` — архитектура, установка, безопасность, runbook

Нужны Python 3.11+, `ip` (iproute2), `dumpcap`, `tshark`.
