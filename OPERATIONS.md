# Fabricator Agent Operations

Короткая шпаргалка по этому репозиторию и по продовой схеме, которую мы разобрали.

## Что есть что

- Этот репозиторий: `C:\Users\reno\RiderProjects\fabricator-agent`
- GitHub-репозиторий агента: `https://github.com/ren0san/fabricator-agent.git`
- Основной файл runtime агента: [agent_main.py](C:\Users\reno\RiderProjects\fabricator-agent\agent_main.py)
- README c install/update: [README.md](C:\Users\reno\RiderProjects\fabricator-agent\README.md)

Связанный backend-репозиторий:

- Локально: `C:\Users\reno\RiderProjects\fabricator`
- Он нужен для Fabricator core/UI/backend, но не является источником кода для отдельного server-side агента.

Ключевая историческая ошибка:

- фиксы сначала были внесены в `fabricator`, а deployed agent обновлялся из `fabricator-agent`
- из-за этого сервер тянул старый код агента, даже когда backend уже был исправлен

## Продовые пути на ноде агента

На remote-host `tunnel-DE`:

- установленный runtime: `/opt/fabricator-agent`
- systemd unit: `/lib/systemd/system/fabricator-agent.service`
- env-файл: `/etc/default/fabricator-agent` или `/etc/default/fabricator-agent.env`
- config: `/etc/fabricator-agent/config.toml`
- локальный git checkout для ручного обновления: `/root/fabricator-agent`

Сервис стартует из:

```bash
/opt/fabricator-agent/.venv/bin/uvicorn agent_main:app --host 0.0.0.0 --port "${AGENT_HTTP_PORT:-8010}"
```

## Что было сломано

### 1. Self-update

Проблема:

- `self-update-agent` часто завершался как `failed with code -15`
- это происходило из-за того, что агент перезапускал сам себя, а текущий процесс умирал от `SIGTERM`
- backend видел это как fail, хотя update мог уже начаться

Что исправлено:

- self-update с `restart=true` запускается detached
- агент возвращает успешный scheduling result вместо ложного fail по `-15`
- в env прокидываются source repo / branch / target version / target build

### 2. Remote-only create-slug

Проблема:

- remote-only агент молча пытался использовать `http://127.0.0.1:8000`
- на ноде Fabricator backend не запущен по дизайну
- поэтому `create-slug` падал с `connection refused`

Что исправлено:

- агент больше не делает неявный fallback в локальный Fabricator API
- если не задан `payload.command`, `AGENT_CREATE_SLUG_COMMAND` или явный `AGENT_LOCAL_API_URL`, агент возвращает понятную конфигурационную ошибку

### 3. Наблюдаемость

Проблема:

- было плохо видно, какую инструкцию агент взял и на чем упал

Что исправлено:

- `status` хранит `last_instruction_id`, `last_instruction_kind`, `last_instruction_error`, `last_instruction_result`
- агент шлет progress `accepted` / `running`
- `last_error` не затирается молча в конце цикла

## Как понять, что на сервере уже правильный агент

Проверить на ноде:

```bash
curl -sS http://127.0.0.1:8010/status | jq
grep -n "FABRICATOR_AGENT_SOURCE_REPO" /opt/fabricator-agent/agent_main.py
grep -n "last_instruction_id" /opt/fabricator-agent/agent_main.py
grep -n "remote agent has no local fabricator API configured" /opt/fabricator-agent/agent_main.py
journalctl -u fabricator-agent -n 80 --no-pager
```

Если `grep` ничего не находит, сервер все еще на старом агенте.

## Эталонная команда обновления агента

Источник должен быть только один:

- `https://github.com/ren0san/fabricator-agent.git`

Команда:

```bash
sudo apt update
sudo apt install -y git jq
cd /root
if [ ! -d /root/fabricator-agent/.git ]; then
  git clone https://github.com/ren0san/fabricator-agent.git /root/fabricator-agent
fi
cd /root/fabricator-agent
git remote set-url origin https://github.com/ren0san/fabricator-agent.git
git remote -v
git fetch --all --prune
git checkout main
git reset --hard origin/main
git log -1 --oneline
grep -n "FABRICATOR_AGENT_SOURCE_REPO" agent_main.py
grep -n "last_instruction_id" agent_main.py
grep -n "remote agent has no local fabricator API configured" agent_main.py
sudo bash scripts/remote_deploy.sh /root/fabricator-agent
sudo systemctl restart fabricator-agent
sleep 5
curl -sS http://127.0.0.1:8010/status | jq
grep -n "FABRICATOR_AGENT_SOURCE_REPO" /opt/fabricator-agent/agent_main.py
grep -n "last_instruction_id" /opt/fabricator-agent/agent_main.py
journalctl -u fabricator-agent -n 80 --no-pager
```

Что обязательно проверить после update:

- `git remote -v` показывает `ren0san/fabricator-agent`
- `git log -1 --oneline` показывает нужный commit
- `grep` находит маркеры в `/root/fabricator-agent/agent_main.py`
- `grep` находит те же маркеры в `/opt/fabricator-agent/agent_main.py`

## Как проверять create-slug

### На backend

Проверить историю команд по агенту:

```bash
python3 - <<'PY'
import json, urllib.request
api = "https://api.thun-der.ru"
token = "YOUR_MASTER_TOKEN"
agent_id = "fbr-7290f53ae59f43d9"
req = urllib.request.Request(
    f"{api}/api/agent/admin/commands?agent_id={agent_id}&limit=30",
    headers={"X-API-Token": token},
)
with urllib.request.urlopen(req) as r:
    print(json.dumps(json.load(r), ensure_ascii=False, indent=2))
PY
```

Проверить remote instances:

```bash
python3 - <<'PY'
import json, urllib.request
api = "https://api.thun-der.ru"
token = "YOUR_MASTER_TOKEN"
req = urllib.request.Request(
    f"{api}/api/agent/admin/instances",
    headers={"X-API-Token": token},
)
with urllib.request.urlopen(req) as r:
    print(json.dumps(json.load(r), ensure_ascii=False, indent=2))
PY
```

### На ноде агента

```bash
curl -sS http://127.0.0.1:8010/status | jq
journalctl -u fabricator-agent -n 100 -f
```

Если `create-slug` реально создал что-то на диске:

```bash
find / -maxdepth 4 -type d -name 'tunnel-de-test' 2>/dev/null
find / -maxdepth 4 -type f -name '*tunnel-de-test*' 2>/dev/null
grep -R "tunnel-de-test" /opt /etc /root 2>/dev/null
```

## Что значит, если slug виден в UI, а на ноде его нет

Это нормальный симптом backend-first записи:

- backend уже создал запись о remote instance
- но агент еще не материализовал ее на хосте

То есть:

- UI видит intent
- диск/сервис на ноде показывают fact

Если в UI slug есть, а локально `Instance does not exist`, значит instruction была поставлена, но выполнение не дошло до реального provisioning.

## Что нужно для remote-only ноды

Remote-only агент сам по себе не умеет магически создавать инстанс без одного из вариантов:

- `payload.command`
- `AGENT_CREATE_SLUG_COMMAND`
- явно настроенного `AGENT_LOCAL_API_URL`

Если локального Fabricator backend на ноде быть не должно, то:

- `AGENT_LOCAL_API_URL` оставлять пустым
- provisioning делать через `AGENT_CREATE_SLUG_COMMAND` или через будущий встроенный workflow

Проверка env:

```bash
cat /etc/default/fabricator-agent 2>/dev/null
cat /etc/default/fabricator-agent.env 2>/dev/null
grep -n "AGENT_CREATE_SLUG_COMMAND" /etc/default/fabricator-agent /etc/default/fabricator-agent.env 2>/dev/null
grep -n "AGENT_LOCAL_API_URL" /etc/default/fabricator-agent /etc/default/fabricator-agent.env 2>/dev/null
```

## Частые причины, если update не помогает

### Обновляется не тот repo

Симптом:

```bash
From https://github.com/mrren0/fabricator-agent
```

Решение:

```bash
cd /root/fabricator-agent
git remote set-url origin https://github.com/ren0san/fabricator-agent.git
```

### Обновился git checkout, но не обновился установленный runtime

Симптом:

- в `/root/fabricator-agent/agent_main.py` строки есть
- в `/opt/fabricator-agent/agent_main.py` строк нет

Решение:

- проверить `scripts/remote_deploy.sh`
- проверить `dpkg-buildpackage`
- проверить, что пакет реально копирует свежий `agent_main.py` в `/opt/fabricator-agent`

### Сервис поднялся слишком рано проверяется

Симптом:

```bash
curl: (7) Failed to connect to 127.0.0.1 port 8010
```

Сразу после restart это может быть просто race. Дать:

```bash
sleep 5
curl -sS http://127.0.0.1:8010/status | jq
```

## Локальные репозитории, которые важно не путать

- `C:\Users\reno\RiderProjects\fabricator-agent`
  Это правильный репозиторий server-side агента.

- `C:\Users\reno\RiderProjects\fabricator`
  Это backend/UI/central Fabricator. Исправления здесь не обновят агент, пока они не перенесены в `fabricator-agent`.

## Как использовать этот файл в следующих сессиях

Если нужно быстро восстановить контекст, достаточно показать этот файл и сказать:

- какой хост обновляем
- какой slug не создается
- какой repo сейчас развернут на ноде

По этому файлу уже можно:

- понять, какой репозиторий править
- дать правильную команду обновления
- проверить, действительно ли агент новый
- понять, почему `create-slug` завис или почему `self-update` не сошелся
