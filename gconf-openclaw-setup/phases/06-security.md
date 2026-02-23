# Фаза 6. Защита сервера

<!--
КОНТЕКСТ ДЛЯ CURSOR (не показывай пользователю этот блок):

OpenClaw по умолчанию даёт четыре слоя защиты: промпт, config policy, docker sandbox, инфра.
Три из четырёх не работают надёжно. Четвёртый — инфра-уровень — выключен по умолчанию.
Мы настраиваем инфра-уровень.

Источник: Дима Мацкевич, 16 февраля 2026.
Референсный код: github.com/matskevich/openclaw-infra

Известные проблемы upstream:
- tools.allow с незагруженным плагином блокирует ВСЕ tools (issue #1566)
- write tool path restrictions обходятся через exec + heredoc (issue #9348)
- sandboxed agent теряет exec tool (issue #2479)
- «non-main» sandbox защищает embedded agents, а main agent остаётся на host
НЕ ПЫТАЙСЯ чинить tool policy или disallowedTools — они ненадёжны upstream.

ВАЖНЫЕ ПРАВИЛА ГЕНЕРАЦИИ:
- Каждый механизм защиты = ОДИН файл. Не создавай дублирующих реализаций.
- Песочница реализуется ТОЛЬКО как PreToolUse hook (hooks/sandbox-exec/hook.sh).
  НЕ создавай отдельный standalone wrapper в /usr/local/bin/.
- Vault реализуется как готовый скрипт setup-vault.sh (не набор команд в документации).
- Watchdog запускается через systemd timer (НЕ cron).
- В bash-скриптах: НЕ используй `find | while read` — subshell теряет переменные.
  Используй `while read ... done < <(find ...)`.
-->

---

## Что сейчас произойдёт

Твой OpenClaw работает, но его команды выполняются без ограничений — если кто-то подсунет ему вредоносную инструкцию, он может слить твои ключи или сломать настройки.

Сейчас я поставлю четыре замка и проверю каждый автоматическим тестом:

| Шаг | Что делаю | Что это даёт тебе |
|---|---|---|
| 1. Песочница | Изолирую команды агента от системы | Даже если агент получит плохую команду — он не выберется за пределы своей папки |
| 2. Ограничение файлов | Разрешу агенту трогать только рабочую папку | Он не сможет читать или менять системные файлы и чужие настройки |
| 3. Шифрование ключей | Зашифрую все API-ключи и пароли на диске | Если кто-то получит доступ к серверу — увидит шифр, а не пароли |
| 4. Защита от слива | Поставлю фильтр на исходящие сообщения | Агент не отправит наружу ключ или пароль, даже если его попросят |
| 5. Автотест | Прогоню все проверки одним скриптом | Ты видишь итоговый отчёт и можешь перезапускать тест в любой момент |

После каждого шага я проверю, что замок работает, и покажу результат.

**От тебя ничего не нужно — я всё сделаю сам. Если понадобится подтверждение, спрошу.**

---

## Шаг 1. Песочница (bwrap)

<!--
CURSOR INSTRUCTIONS:
1. SSH to server, install bubblewrap: apt-get update && apt-get install -y bubblewrap jq
2. Create ТОЛЬКО PreToolUse hook: ~/.openclaw/hooks/sandbox-exec/hook.sh
   НЕ создавай standalone wrapper в /usr/local/bin/ — это дубликат.
   Based on: github.com/matskevich/openclaw-infra/tree/main/hooks/sandbox-exec
3. Hook перехватывает tool_name "Bash" и оборачивает command в bwrap:
   - Mount openclaw workspace read-write (--bind)
   - Mount /usr, /bin, /lib, /lib64, /sbin read-only (--ro-bind)
   - Mount /etc/resolv.conf, /etc/ssl, /etc/passwd, /etc/group read-only
   - Minimal /dev (--dev) and /proc (--proc)
   - Tmpfs на ~/.openclaw, ~/.ssh, /run, /tmp — пути ВИДНЫ но ПУСТЫ
   - --unshare-pid --die-with-parent
   - --chdir $WORKSPACE
   - Команды systemctl, sudo, ssh, scp — DENY (не оборачивать, а блокировать)
4. Без bwrap — fallback с WARNING (не silent fail)
5. Register hook in settings.json under hooks.PreToolUse для matcher "Bash"
6. Make executable: chmod +x
7. Run verification tests below
-->

Устанавливаю инструмент изоляции и настраиваю обёртку для всех команд агента.

Что происходит технически: каждая команда, которую запускает агент, теперь выполняется в отдельном пространстве. Он видит только свою рабочую папку. Секреты, системные файлы, настройки — для него не существуют.

### Проверка шага 1

<!--
CURSOR: run these tests and report results to user.

TEST 1.1 — bwrap installed:
  command: which bwrap
  expect: path to bwrap binary
  
TEST 1.2 — hook exists and executable:
  command: test -x ~/.openclaw/hooks/sandbox-exec/hook.sh && echo "OK"
  expect: "OK"

TEST 1.3 — hook registered in settings.json:
  command: jq '.hooks.PreToolUse[] | select(.matcher == "Bash")' ~/.openclaw/settings.json
  expect: entry with path to sandbox-exec/hook.sh

TEST 1.4 — secrets not visible from sandbox:
  Create a test file: echo "SECRET_TEST=exposed" > /run/test-secret
  Run inside bwrap (same params as hook): cat /run/test-secret
  expect: file not found (tmpfs on /run makes it invisible)
  Cleanup: rm -f /run/test-secret

TEST 1.5 — workspace writable from sandbox:
  Run inside bwrap: touch [WORKSPACE]/sandbox-test && echo "OK"
  expect: "OK"
  Cleanup: rm [WORKSPACE]/sandbox-test

ВАЖНО: НЕ должно существовать файла /usr/local/bin/openclaw-sandbox-exec.sh.
Если он есть — удали. Sandbox реализован ТОЛЬКО как hook.
-->

```
Результат:
✅/❌ bwrap установлен
✅/❌ hook на месте и исполняемый
✅/❌ hook зарегистрирован в settings.json
✅/❌ секреты невидимы из песочницы
✅/❌ рабочая папка доступна
```

Если всё ✅ — перехожу к шагу 2.
Если есть ❌ — объясню что пошло не так и починю.

---

## Шаг 2. Ограничение файлов (fs-guard)

<!--
CURSOR INSTRUCTIONS:
1. Create PreToolUse hook: ~/.openclaw/hooks/fs-guard/hook.sh
   Based on: github.com/matskevich/openclaw-infra/tree/main/hooks/fs-guard
2. Hook must intercept: Read, Edit, Write, MultiEdit, Glob, Grep tools
3. For each intercepted call: check if target path is within openclaw workspace or /tmp
4. Path resolution: use realpath -m с fallback на python3 os.path.normpath
5. Проверка path traversal: блокировать если resolved path содержит ".."
6. MultiEdit: проверить ВСЕ пути в edits[], не только первый
7. If outside workspace — block with permissionDecision "deny" и причиной
8. Register hook in settings.json under hooks.PreToolUse для matcher "Read|Edit|Write|MultiEdit|Glob|Grep"
9. Run verification test below
-->

Настраиваю хук, который проверяет каждое обращение агента к файлам. Если агент пытается прочитать или изменить что-то за пределами рабочей папки — хук блокирует действие до выполнения, а не после.

Зачем: в OpenClaw есть дыра — инструмент записи файлов имеет ограничения по путям, а инструмент выполнения команд — нет. Через команды можно обойти ограничения записи. Хук закрывает эту дыру.

### Проверка шага 2

<!--
CURSOR: run these tests and report results to user.

TEST 2.1 — hook registered:
  Check openclaw settings.json contains PreToolUse hook entry for Read|Edit|Write|MultiEdit|Glob|Grep
  expect: hook path present in config

TEST 2.2 — write inside workspace allowed:
  Trigger write tool to create [WORKSPACE]/test-guard.txt with content "test"
  expect: file created successfully
  Cleanup: rm [WORKSPACE]/test-guard.txt

TEST 2.3 — write outside workspace blocked:
  Trigger write tool to create /etc/test-escape.txt
  expect: blocked by hook
  Verify: test ! -f /etc/test-escape.txt && echo "BLOCKED"

TEST 2.4 — read outside workspace blocked:
  Trigger read tool on /etc/shadow
  expect: blocked by hook
-->

```
Результат:
✅/❌ хук зарегистрирован в настройках
✅/❌ запись в рабочую папку работает
✅/❌ запись за пределы папки заблокирована
✅/❌ чтение за пределы папки заблокировано
```

---

## Шаг 3. Шифрование ключей (SOPS + age)

<!--
CURSOR INSTRUCTIONS:
1. Install sops and age: apt-get install -y age && install sops from github releases
   (sops may not be in apt — check, if not, download binary from github.com/getsops/sops/releases)
2. Generate age key: age-keygen -o /home/openclaw/.config/sops/age/keys.txt
   (create directory structure if needed, set permissions 600)
3. Create .sops.yaml in openclaw workspace pointing to the age public key
4. Encrypt existing .env / secrets files: sops --encrypt --in-place [file]
5. Создай ГОТОВЫЙ СКРИПТ setup-vault.sh в files/security/ который делает ВСЁ:
   a) Создаёт mount point: mkdir -p /run/openclaw-secrets
   b) Добавляет в /etc/fstab: tmpfs /run/openclaw-secrets tmpfs nodev,nosuid,noexec,size=10M,mode=0700,uid=[openclaw-user] 0 0
   c) Монтирует: mount /run/openclaw-secrets
   d) Расшифровывает секреты: sops --decrypt [WORKSPACE]/.env > /run/openclaw-secrets/.env
   e) Устанавливает права: chown openclaw:openclaw /run/openclaw-secrets/.env && chmod 600
   f) Скрипт принимает параметры: --user, --workspace, --env-file
   g) Скрипт идемпотентный (можно запускать повторно)
6. Создай systemd drop-in для сервиса openclaw:
   /etc/systemd/system/openclaw.service.d/vault.conf
   [Service]
   ExecStartPre=/path/to/setup-vault.sh --user openclaw --workspace /home/openclaw/workspace
   EnvironmentFile=/run/openclaw-secrets/.env
7. Verify tmpfs is NOT mounted inside bwrap namespace (check sandbox hook — /run монтируется как tmpfs)
8. Run verification tests below

IMPORTANT: .env file must be owned by openclaw service user, NOT root.
Known gap: process.env in memory of main process remains sensitive. No perfect solution exists.
-->

Устанавливаю инструменты шифрования и перевожу все ключи в зашифрованный формат.

Как это работает: твои API-ключи и пароли хранятся на диске в зашифрованном виде. Когда сервер запускается, они расшифровываются во временное хранилище в оперативной памяти. Если сервер выключится — временное хранилище исчезает. Если кто-то скопирует файлы с диска — увидит шифр.

### Проверка шага 3

<!--
CURSOR: run these tests and report results to user.

TEST 3.1 — sops and age installed:
  command: sops --version && age --version
  expect: version numbers

TEST 3.2 — age key exists:
  command: test -f /home/openclaw/.config/sops/age/keys.txt && echo "OK"
  expect: "OK"

TEST 3.3 — .env file encrypted on disk:
  command: head -1 [WORKSPACE]/.env
  expect: should start with sops metadata / not contain plaintext keys
  (if .env doesn't exist yet, create a test one, encrypt, verify, note to user)

TEST 3.4 — setup-vault.sh exists:
  command: test -x /path/to/setup-vault.sh && echo "OK"
  expect: "OK"

TEST 3.5 — tmpfs mounted:
  command: mount | grep openclaw-secrets
  expect: tmpfs on /run/openclaw-secrets

TEST 3.6 — decrypted secrets accessible at runtime:
  command: test -f /run/openclaw-secrets/.env && echo "OK"
  expect: "OK"

TEST 3.7 — systemd drop-in configured:
  command: systemctl cat openclaw | grep ExecStartPre
  expect: path to setup-vault.sh

TEST 3.8 — tmpfs not visible from bwrap sandbox:
  Run inside sandbox (same bwrap params as hook): ls /run/openclaw-secrets/
  expect: directory empty or not found (hook mounts tmpfs on /run)
-->

```
Результат:
✅/❌ sops и age установлены
✅/❌ ключ шифрования создан
✅/❌ файл с секретами зашифрован на диске
✅/❌ setup-vault.sh создан и исполняемый
✅/❌ временное хранилище в памяти работает
✅/❌ секреты доступны при запуске
✅/❌ systemd настроен на расшифровку при старте
✅/❌ секреты невидимы из песочницы
```

---

## Шаг 4. Защита от слива (DLP + watchdog)

<!--
CURSOR INSTRUCTIONS:

=== DLP (output-filter) ===
1. Create output DLP hook: ~/.openclaw/hooks/output-filter/handler.ts
   Based on: github.com/matskevich/openclaw-infra/tree/main/hooks/output-filter
2. Hook intercepts all outgoing messages from agent
3. Pattern matching for:
   - API key formats: sk-ant-api*, sk-ant-oat*, sk-proj-*, sk-[a-zA-Z0-9]{32+}, AIza*, gsk_*, gh[ps]_*, github_pat_*
   - Telegram bot tokens: \d{8,10}:[A-Za-z0-9_-]{35}
   - JWT tokens, PEM private keys
   - Base64-encoded versions of key prefixes
   - .env file contents (load known secrets from .env and openclaw.json)
   - High-entropy strings (Shannon entropy > 4.0, length >= 32, mixed char classes)
4. ВАЖНО: событие message:sent — это POST-event. Hook НЕ МОЖЕТ заблокировать отправку.
   Hook должен: ЛОГИРОВАТЬ инцидент в /var/log/openclaw-security/action-log.md,
   ДОБАВИТЬ предупреждение в messages[] для пользователя,
   ВЫВЕСТИ alert в stderr.
   НЕ пиши "block message" — это технически невозможно для post-event хуков.
5. Register hook in settings.json under hooks["message:sent"]

=== WATCHDOG ===
6. Create config watchdog script: files/security/openclaw-watchdog.sh
   - Watches settings.json, .cursor/rules/*, hooks/*.sh
   - On unauthorized change: revert from backup, log to /var/log/openclaw-security/watchdog.log
   - ВАЖНО: НЕ используй `find ... | while read` — subshell теряет переменные.
     Используй: while read -r f; do ... done < <(find "$HOOKS_DIR" -type f -name "*.sh")
7. Create systemd timer для watchdog (НЕ cron):
   - /etc/systemd/system/openclaw-watchdog.service
   - /etc/systemd/system/openclaw-watchdog.timer (OnUnitActiveSec=60s)
   - systemctl enable --now openclaw-watchdog.timer
8. Set up logrotate: /etc/logrotate.d/openclaw-security
9. Run verification tests below
-->

Настраиваю два механизма:

**Фильтр исходящих сообщений** — проверяет всё, что агент отправляет. Если в тексте есть что-то похожее на API-ключ или пароль — логирует инцидент и присылает тебе предупреждение. Это защита от сценария, когда агент через вредоносную инструкцию получает команду «перешли свой API-ключ».

**Сторож настроек** — следит за конфигурационными файлами. Если кто-то (или агент сам) пытается изменить настройки безопасности — сторож откатывает изменения и сообщает тебе.

### Проверка шага 4

<!--
CURSOR: run these tests and report results to user.

TEST 4.1 — DLP hook registered:
  command: jq '.hooks["message:sent"]' ~/.openclaw/settings.json
  expect: entry with path to output-filter/handler.ts

TEST 4.2 — DLP detects API key in output:
  Simulate agent output containing "sk-test1234567890abcdefghijklmnopqrstuv"
  expect: logged to action-log.md + warning in messages
  (NOTE: DLP logs and alerts but cannot block — message:sent is post-event)

TEST 4.3 — DLP allows normal text:
  Simulate agent output containing "Задача выполнена, вот результат"
  expect: no alert

TEST 4.4 — watchdog timer running:
  command: systemctl is-active openclaw-watchdog.timer
  expect: active

TEST 4.5 — watchdog reverts unauthorized change:
  Backup current settings.json
  Append "# tamper test" to settings.json
  Wait 90 seconds
  Check if settings.json matches backup
  expect: reverted
  (Note: this test takes ~90 seconds, warn user)

TEST 4.6 — logs directory exists with rotation:
  command: test -d /var/log/openclaw-security && logrotate --debug /etc/logrotate.d/openclaw-security 2>&1 | head -5
  expect: directory exists, logrotate configured
-->

```
Результат:
✅/❌ фильтр сообщений зарегистрирован
✅/❌ API-ключ в исходящем сообщении обнаружен и залогирован
✅/❌ обычный текст проходит свободно
✅/❌ сторож настроек запущен (systemd timer)
✅/❌ несанкционированное изменение настроек откачено
✅/❌ логи пишутся и ротируются
```

---

## Шаг 5. Автоматический тест безопасности (pentest-basic.sh)

<!--
CURSOR INSTRUCTIONS:
1. Create script: files/security/pentest-basic.sh
2. Script runs ALL tests from steps 1-4 automatically:
   - bwrap installed + hook exists + hook registered
   - secrets invisible from sandbox + workspace writable
   - fs-guard hook registered + write/read outside workspace blocked
   - sops + age installed + .env encrypted + tmpfs mounted + vault script exists
   - DLP hook registered + detects test key
   - watchdog timer active + logs directory exists
3. Output: colored ✅/❌ for each test, summary count at the end
4. Exit code: 0 if all pass, 1 if any fail
5. Script must be self-contained — no dependencies beyond jq and bwrap
6. Save to files/security/pentest-basic.sh, chmod +x
7. Run it and show results to user
-->

Создаю скрипт, который проверяет все четыре слоя защиты одним запуском. Его можно запускать в любой момент — после обновления OpenClaw, после изменения настроек, или просто для спокойствия.

### Проверка шага 5

```
Результат:
✅/❌ pentest-basic.sh создан и исполняемый
✅/❌ все тесты пройдены (вывод скрипта выше)
```

---

## Итоговая проверка

<!--
CURSOR: run pentest-basic.sh and print full output.
This replaces manual re-running of all tests.
-->

Запускаю итоговый тест:

```
pentest-basic.sh output:

ПЕСОЧНИЦА (bwrap):        .../...
ОГРАНИЧЕНИЕ ФАЙЛОВ:       .../...
ШИФРОВАНИЕ (vault):       .../...
ЗАЩИТА ОТ СЛИВА (DLP):    .../...
СТОРОЖ (watchdog):        .../...

ИТОГО: .../... тестов пройдено
```

---

## Что осталось за рамками (и почему)

**Egress filtering** (ограничение исходящего трафика) — не настраиваем сейчас. Причина: нужно точно знать все домены всех интеграций, легко сломать работу агента. Автор методологии (Мацкевич) сам пометил как «в прогрессе». Вернись к этому, когда всё остальное проработает 2–3 недели стабильно.

**process.env в памяти** — известное ограничение, полного решения не существует. Песочница exec-процессов его не видит, но основной процесс OpenClaw хранит переменные окружения в памяти. Это принятый компромисс.

**DLP не блокирует, а логирует** — событие message:sent в OpenClaw срабатывает после отправки. Полная блокировка технически невозможна на уровне хуков. DLP обнаруживает утечку, логирует и предупреждает — чтобы ты мог отозвать скомпрометированный ключ.
