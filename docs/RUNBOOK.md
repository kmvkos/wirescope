# Runbook WireScope

**Русский** · [English](en/RUNBOOK.md)

Это рабочая памятка для эксплуатации уже установленного appliance. Установка и first-time setup описаны в [INSTALLATION.md](INSTALLATION.md).

Команды ниже ориентированы на system install в `/opt/wirescope`. Для `--user-install` используйте `systemctl --user` / `journalctl --user` и пользовательские пути.

## Быстрая проверка состояния

```bash
systemctl is-active wirescope-api wirescope-worker
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
/opt/wirescope/.venv/bin/python -m appliance verify --project-root /opt/wirescope
/opt/wirescope/.venv/bin/python -m appliance detect
```

Что означают endpoints:

- `/api/health` — API process жив;
- `/api/ready` — дополнительно готовы DB migrations, worker heartbeat и обязательные binaries.

`/api/health` может быть `ok`, даже если worker не работает. Это нормальное различие между liveness и readiness.

## Логи

Последний час:

```bash
journalctl \
  -u wirescope-api \
  -u wirescope-worker \
  --since -1h
```

Следить в реальном времени:

```bash
journalctl -f -u wirescope-api -u wirescope-worker
```

Kiosk:

```bash
journalctl -u wirescope-kiosk -e
```

Если installer установил journald drop-in WireScope, журнал ограничивается по размеру/времени, чтобы appliance не забил диск логами.

## Проверка login

Локально:

```text
http://127.0.0.1:8000/
```

Через reverse proxy:

```text
https://<host>/
```

Default GUI username обычно:

```text
auditor
```

Первичный сгенерированный пароль после install лежит в:

```text
/etc/wirescope/initial-admin.txt
```

После переноса в password manager файл следует удалить.

Если login проходит, но browser тут же снова показывает login screen, проверьте схему HTTP/HTTPS. При `Secure` session cookie страницу нужно открывать по HTTPS.

## Смена/сброс пароля

Обычная смена: в GUI → **«Сменить пароль»**.

При lock-out:

```bash
/opt/wirescope/.venv/bin/python \
  -m appliance set-password auditor
```

Команда обновляет пароль в рабочей SQLite, отзывает sessions пользователя и пишет новый пароль в `0600` file.

## API не отвечает

Проверить:

```bash
systemctl status wirescope-api
journalctl -u wirescope-api -e
ss -lntp | grep ':8000\|:8443' || true
```

Проверить environment:

```bash
sudo cat /etc/wirescope/wirescope.env
```

Не публикуйте содержимое environment file целиком в issue/chat, если позже там появятся чувствительные пути/параметры.

Если используется reverse proxy:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

сначала должен работать локально. Только потом диагностировать Caddy/nginx/TLS/firewall.

## `/api/ready` возвращает 503

Проверить body ответа:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

Readiness зависит от:

- database accessible;
- migrations current;
- worker heartbeat current;
- `dumpcap`;
- `tshark`;
- `nmap`.

### Migrations не current

```bash
sudo -u wirescope \
  env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/alembic \
  -c /opt/wirescope/alembic.ini upgrade head
```

После этого:

```bash
sudo systemctl restart wirescope-worker wirescope-api
```

### Worker не ready

```bash
systemctl status wirescope-worker
journalctl -u wirescope-worker -e
```

Если worker был остановлен надолго, старые running jobs при startup станут `interrupted`. Это ожидаемое recovery behavior.

## Packet capture не работает

Проверить `dumpcap`:

```bash
getent group wireshark
getcap /usr/bin/dumpcap
stat -c '%U:%G %a' /usr/bin/dumpcap
sudo -u wirescope /usr/bin/dumpcap -D
getcap /opt/wirescope/.venv/bin/python || true
```

Ожидаемо:

```text
/usr/bin/dumpcap
root:wireshark
0750
cap_net_admin,cap_net_raw=eip
```

Python capabilities быть не должно.

Если `dumpcap -D` не работает от `wirescope`, повторно выполнить installer verification/setup:

```bash
sudo /opt/wirescope/.venv/bin/python \
  -m appliance verify --project-root /opt/wirescope
```

и проверить package-specific Wireshark configuration.

### User install

Для `--user-install` процесс должен получить группу `wireshark` через `sg wireshark`.

После изменения group membership:

```bash
systemctl --user daemon-reload
systemctl --user restart wirescope-api wirescope-worker
```

Logout обычно не требуется именно потому, что units используют `sg wireshark`.

## Capture видит мало трафика

Это не обязательно ошибка.

Без SPAN/mirror switch не отправляет на порт весь traffic VLAN. Даже promiscuous capture видит только кадры, реально дошедшие до NIC.

Обычно это:

- broadcasts;
- flooded traffic;
- multicast, доставленный на port;
- unicast на MAC WireScope;
- control protocols вроде LLDP/CDP/STP, если они приходят на port.

Для полного наблюдения чужого unicast traffic нужен SPAN/mirror/TAP.

## VLAN ID не определяется

Access port часто отправляет untagged frames. В таком случае WireScope корректно оставляет VLAN ID неизвестным.

Проверяйте отдельно:

- были ли 802.1Q tagged frames;
- LLDP/CDP advertised VLAN metadata;
- существующие VLAN subinterfaces;
- конфигурацию switch port.

LLDP PVID/native VLAN и 802.1Q tag — не одно и то же.

## Active discovery не запускается

Проверить:

1. подтверждён ли scope;
2. есть ли L3 address нужного family;
3. `ip route get <target>` использует выбранный interface;
4. target не запрещён scope policy;
5. address count не превышает profile cap;
6. Nmap присутствует;
7. нет другого job, удерживающего `interface:<name>`.

Команды:

```bash
ip -j addr
ip -j route
ip route get <target>
nmap --version
curl -sS http://127.0.0.1:8000/api/ready
```

Passive capture может работать без IP, active discovery — нет: Nmap нужен реальный L3 path.

## Protocol module не запустился

Это может быть нормальным behavior.

Проверить:

- найден ли подходящий service в inventory;
- address внутри confirmed scope;
- module safety class;
- binary установлен;
- module не `never-default`.

Availability tools:

```bash
command -v ssh-audit
command -v openssl
command -v curl
command -v dig
command -v smbclient
command -v snmpget
command -v ldapsearch
```

Missing optional tool не делает весь audit failed: observation получает `tool_unavailable`.

## Reboot во время audit

После старта worker:

| Состояние до reboot | После recovery |
| --- | --- |
| `queued` | остаётся `queued` |
| `running` | `interrupted`, `application_restart` |
| `cancelled` | остаётся `cancelled` |
| terminal | не меняется |

Автоматического retry/resume нет.

После reboot:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

когда worker снова ready, открыть audit из history в GUI.

Reload browser или restart kiosk сами по себе running job не останавливают.

## Cancellation зависла

Проверить worker log:

```bash
journalctl -u wirescope-worker -e
```

Cancellation должна дойти до cooperative token и завершить subprocess group.

Если worker process был убит жёстко, job будет обработан startup recovery как `interrupted`.

## Kiosk не запустился

Проверить:

```bash
systemctl status wirescope-kiosk
journalctl -u wirescope-kiosk -e
```

Вернуть login prompt на tty1:

```bash
sudo systemctl start getty@tty1
```

Проверить Chromium:

```bash
command -v chromium || command -v chromium-browser
```

На VMware также проверить Xorg/video stack.

Kiosk restart не требует restart API/worker:

```bash
sudo systemctl restart wirescope-kiosk
```

## Reverse proxy не работает

Сначала локальный API:

```bash
curl -sS http://127.0.0.1:8000/api/health
```

Затем proxy:

```bash
systemctl status caddy || systemctl status nginx
```

Проверить listener:

```bash
ss -lntp | grep ':443'
```

И firewall.

Примеры конфигурации: `packaging/proxy/`.

Если WireScope установлен с `--trust-proxy`, с другого ПК нужно открывать HTTPS URL, иначе `Secure` session cookie не будет работать по обычному HTTP.

## Backup

Online backup поддерживается, но перед большим maintenance можно остановить службы для более простой операционной процедуры:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup

sudo systemctl start wirescope-worker wirescope-api
```

Backup по умолчанию:

```text
/var/lib/wirescope/backups/<UTC timestamp>/
```

Он содержит SQLite и, если не отключено, evidence tree.

Backup хранить как чувствительные audit data.

## Restore

Службы должны быть остановлены:

```bash
sudo systemctl stop wirescope-api wirescope-worker

sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance restore \
  /var/lib/wirescope/backups/TIMESTAMP

sudo systemctl start wirescope-worker wirescope-api
```

После restore:

```bash
curl -sS http://127.0.0.1:8000/api/ready
```

## Upgrade

Перед upgrade:

```bash
sudo -u wirescope env WIRESCOPE_DATA_DIR=/var/lib/wirescope \
  /opt/wirescope/.venv/bin/python -m appliance backup
```

Обновление:

```bash
cd /opt/wirescope
git pull
sudo ./packaging/upgrade.sh --project-root /opt/wirescope
```

Проверка:

```bash
curl -sS http://127.0.0.1:8000/api/ready
systemctl status wirescope-api wirescope-worker
```

Optional protocol tools, которых нет в distro repositories, могут быть пропущены с warning. Nikto/Nuclei installer по умолчанию не ставит.

## Rollback

1. Stop API/worker.
2. Restore pre-upgrade backup.
3. Checkout previous known-good revision.
4. Reinstall checkout в `.venv`.
5. Start worker, затем API.
6. Проверить readiness/login.

Не использовать `alembic downgrade` как универсальный rollback без тестирования конкретной migration.

## Disk usage

Проверить:

```bash
du -sh /var/lib/wirescope
find /var/lib/wirescope/evidence -type f | wc -l
df -h /var/lib/wirescope
```

Listen/record PCAP может быстро расходовать место, особенно если operator регулярно сохраняет captures.

Автоматической полной retention policy для зарегистрированных audits/evidence пока нет, поэтому cleanup нужно планировать отдельно и не удалять файлы из evidence tree вручную без понимания DB references.

## Dependency inventory

```bash
/opt/wirescope/.venv/bin/python -m appliance inventory
```

или документ:

```text
packaging/inventory/DEPENDENCIES.md
```

## Перед обращением за диагностикой

Полезно собрать:

```bash
/opt/wirescope/.venv/bin/python -m appliance detect
/opt/wirescope/.venv/bin/python -m appliance verify --project-root /opt/wirescope
curl -sS http://127.0.0.1:8000/api/health
curl -sS http://127.0.0.1:8000/api/ready
systemctl status wirescope-api wirescope-worker --no-pager
journalctl -u wirescope-api -u wirescope-worker --since -10m --no-pager
```

Не прикладывайте raw PCAP, database, password files или полный evidence tree без явной необходимости: там могут быть чувствительные данные сети.
