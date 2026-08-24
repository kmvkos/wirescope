# GUI WireScope

**Русский** · [English](en/GUI_MODEL.md)

GUI — основной интерфейс оператора. Для обычного аудита shell не нужен: создание audit, passive capture, подтверждение scope, active discovery, protocol audits, findings и report доступны из браузера.

Frontend — клиент durable API. Он не управляет временем жизни worker job напрямую: закрытие вкладки, reload или restart kiosk не отменяют работу.

## Где запускается GUI

Поддерживаются два варианта.

### Локальный kiosk

Chromium работает на самом WireScope appliance:

```text
http://127.0.0.1:8000/
```

Сеть управления до другого ПК не требуется.

System kiosk работает на `tty1` без GNOME/KDE/XFCE. На VMware используется Xorg/xinit, на другом подходящем железе — Cage либо xinit fallback.

### Удалённый browser

Оператор открывает WireScope с другого компьютера. Предпочтительный production path:

```text
browser → HTTPS → Caddy/nginx → 127.0.0.1:8000
```

Подробнее: [INSTALLATION.md](INSTALLATION.md) и [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Технологии frontend

Frontend намеренно остаётся без build framework:

```text
frontend/
├── index.html
├── app.js
├── i18n.js
└── style.css
```

Это vanilla HTML/CSS/JavaScript.

При этом приложение уже достаточно большое: здесь находятся wizard аудита, status polling, inventory screens, findings, reports, network settings, login/password flow и отдельный listen/record режим.

## Основной audit flow

```text
login
  ↓
home
  ↓
new audit
  ↓
environment / interface
  ↓
network + scope
  ↓
profile
  ↓
confirmation
  ↓
passive / active / protocol jobs
  ↓
summary
  ↓
assets / observations / assessment / findings
  ↓
report
```

Home также содержит отдельные действия:

- **Прослушивание**;
- **Сеть**;
- **Сменить пароль**;
- просмотр предыдущих audits.

## Роли

Локальные роли две:

- `auditor`;
- `viewer`.

| Действие | Auditor | Viewer |
| --- | --- | --- |
| Login, просмотр audits/jobs/inventory/findings/reports | да | да |
| Смена собственного пароля | да | да |
| Создание audit | да | нет |
| Запуск/отмена jobs | да | нет |
| Запуск/остановка listen capture | да | нет |
| Просмотр/download сохранённых captures | да | да |
| Изменение network settings | да | нет |
| Suppress / accept risk / reopen finding | да | нет |
| Генерация report | да | нет |

Role enforcement выполняется backend, а не только скрытием кнопок в JavaScript.

## Login и session

После успешной аутентификации backend выставляет HttpOnly session cookie.

Свойства:

- random token;
- `SameSite=strict`;
- token digest в SQLite — SHA-256;
- `Secure` при trusted reverse proxy или direct TLS.

Если `Secure` cookie используется, а оператор открыл страницу по обычному HTTP, login визуально может «не сохраняться». GUI показывает предупреждение для такого случая.

## Смена пароля

На home есть **«Сменить пароль»**.

Пользователь вводит:

1. текущий пароль;
2. новый пароль;
3. подтверждение нового пароля.

Backend проверяет текущий hash, обновляет пароль и отзывает остальные sessions этого пользователя. Текущая browser session остаётся активной.

CLI `appliance set-password` нужен в основном для lock-out recovery.

## Layout

Компактная базовая раскладка рассчитана на 480×320 landscape kiosk.

Основные ограничения:

- одна колонка;
- минимум 44 px для touch targets;
- компактный header;
- отдельная scrollable content area;
- подтверждения/stop dialog используют `role="alertdialog"`.

На ширине от 900px включается более плотная desktop/laptop раскладка: grids, больше информации в строке и увеличенный report preview.

Цель — не делать отдельные два frontend'а для kiosk и laptop.

## Job progress

GUI периодически опрашивает durable job status.

Если poll временно упал:

- показывается warning;
- polling повторяется с backoff;
- job не отменяется.

Stop — отдельное действие `auditor` с confirmation dialog.

Активный audit id хранится в `sessionStorage`, чтобы после reload можно было вернуться к progress/summary.

Это локальная UI convenience, а не source of truth. Реальное состояние job лежит в SQLite на стороне backend/worker.

## Summary, observations, assessment и findings

Эти экраны разделены специально.

### Summary

Короткая картина аудита:

- capture interface;
- был ли на нём L3 address;
- frame count;
- реально увиденные tagged VLAN IDs;
- LLDP/CDP neighbors;
- segment/access-vs-trunk note;
- состояние дальнейших стадий.

### Observations

Нормализованные факты protocol modules.

Например, TLS session/certificate, SSH algorithms или HTTP response metadata.

### Assessment

Интерпретации passive evidence с confidence: VLAN hints, neighbors, STP, ARP/DHCP и т. п.

### Findings

Security/diagnostic rules с severity, recommendation и state.

Passive sensor hit не становится finding только потому, что он существует.

## VLAN display

GUI следует той же модели, что и backend/report.

802.1Q VLAN ID отображается как «увиденный в traffic» только если tag реально присутствовал в кадре.

Если access-port передаёт untagged frames, WireScope показывает факт untagged traffic, но не придумывает VLAN ID.

LLDP/CDP advertised native/voice VLAN показывается как neighbor data и не смешивается с frame tag.

## «Прослушивание» / Listen & Record

Это отдельный режим, не то же самое, что короткий passive capture внутри audit.

Оператор задаёт:

- interface;
- optional BPF/tcpdump filter;
- duration;
- max PCAP size.

Создаётся job:

```text
packet_capture
```

В этом режиме `dumpcap` работает promiscuous и итоговый PCAP сохраняется в evidence store.

Default параметры:

```text
duration: 120 s
max file size: 16 MiB
```

Policy maximums по текущим settings:

```text
duration: 1800 s
max file size: 64 MiB
filter length: 512 chars
```

Duration `0` поддерживается как capture «до Stop», при этом filesize limit остаётся safety boundary.

### Что реально даёт promiscuous mode

Promiscuous mode не заставляет switch прислать host'у весь traffic сегмента.

Без SPAN/mirror NIC обычно увидит:

- broadcast;
- flooded traffic;
- multicast, который реально дошёл до порта;
- unicast на собственный MAC;
- другой traffic, который switch по своей логике отправил на этот port.

`dumpcap` запишет всё, что NIC получил, но не «всю сеть» магическим образом.

### BPF filter

Filter проходит отдельную нормализацию/валидацию и передаётся как один аргумент `dumpcap -f`.

Shell для filter не используется.

## Network screen

GUI может показывать и менять host network configuration через backend `NetworkService`/appliance `netctl` boundary.

При потенциально опасном изменении, которое может потерять текущий management path, backend требует дополнительное confirmation. Frontend не может просто обойти эту проверку.

## Reports

GUI умеет:

- запустить report generation (`auditor`);
- показать историю reports;
- открыть HTML preview;
- скачать HTML/JSON export.

Viewer может читать уже существующие reports, но не генерировать новые.

PDF пока возвращает `422 pdf_not_available`.

## Ошибки

GUI не должен превращать backend error в «ничего не найдено».

Типичные варианты отображаются отдельно:

- validation error;
- worker not ready;
- provider missing;
- timeout;
- cancellation;
- partial result;
- authorization/role error;
- network apply confirmation/error.

## Kiosk lifecycle

Kiosk process независим:

```text
wirescope-api      survives Chromium restart
wirescope-worker   survives Chromium restart
wirescope-kiosk    may restart independently
```

Поэтому reload/restart display не отменяет активный audit.

Это одно из ключевых требований GUI: экран — не executor.

## Browser tests

Основные GUI/API сценарии тестируются fixture-based. Optional Playwright tests помечены `browser` и skip'аются, если Playwright/Chromium недоступен.

Отсутствие Chromium в headless CI не считается падением backend test suite.
