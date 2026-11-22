# Архитектура и модель угроз

## Компоненты и границы доверия

```text
Windows Event Log (Security, RCM, LSM)
  EvtSubscribe + EvtNext + bookmarks
           |
           v
RDPGuardService [LocalSystem]
  strict XML parser -> event + decision + bookmark transaction -> SQLite WAL
  policy / whitelist / WTS admin protection / limits / expiry
  bounded firewall batches -> COM HNetCfg.FwPolicy2 -> read-back verification
           ^
  local named pipe: ACL SYSTEM + elevated Administrators + RDPGuardWeb service SID
  Windows peer identity + panel session + command validation + audit
           |
RDPGuardWeb [LocalService + service SID]
  FastAPI / static assets / Jinja2 / localhost:8787
           ^
  authenticated browser in RDS session (untrusted until login)

Independent SYSTEM task RDPGuardRollback -> emergency latch + owned-rule removal
Elevated CLI -> named pipe, or independent emergency/bootstrap commands
```

`src/rdp_guard/models.py` проверяет параметры и адреса; `events.py` разбирает события; `storage.py` управляет SQLite; `guard.py` реализует политику и транзакции; `firewall.py` строит узкие правила; `windows/` содержит настоящие API-адаптеры; `auth.py` — аутентификацию и повторную проверку прав; `web/` — непривилегированный интерфейс.

## Персистентность

В `C:\ProgramData\RDPGuard\guard.db` хранятся события, bookmarks по каналам, настройки, whitelist, решения и история блокировок, счётчики повторных нарушений, администраторы панели, хеши session tokens, ограничения входов и аудит. SQLite использует WAL, `synchronous=FULL`, busy timeout и транзакции. Событие, решение и bookmark записываются одной транзакцией. Повторная доставка после аварии безопасна.

Идентификатор события содержит канал, Record ID, исходную временную метку и Event ID. Record ID после очистки может использоваться снова; такое новое событие сохраняется. Ошибка парсинга фиксируется в аудите без принятия решения, bookmark продвигается, чтобы повреждённая запись не остановила канал. При stale bookmark фиксируется разрыв и выполняется чтение с самой старой доступной записи с дедупликацией. Уже удалённые ОС записи восстановить невозможно.

Временное окно считается SQL-запросом по индексированным IP/времени. Исторические события вне текущего окна и события с недостоверными адресами не вызывают блокировки. После истечения/снятия решения прошлые события не используются повторно. В Monitor Only создаются только предложения; при активации они закрываются и не превращаются автоматически в действующие правила.

## Протокол IPC

Одна JSON-команда на соединение: `op`, `args`, `token`, `csrf`. Сервер не принимает пути к исполняемым файлам, команды оболочки, SQL или произвольные имена API. Идентичность приходит из Windows access token через impersonation, а не из JSON. Веб-идентичность обязана предъявлять действующую сессию для чтения и CSRF для изменения. CLI требует включённую группу Administrators / SYSTEM.

Именованный канал `\\.\pipe\RDPGuard.v1` использует message mode, запрет удалённых клиентов и явный DACL. Веб-SID не получает право создавать экземпляры сервера. Клиент сверяет PID и конфигурацию процесса с зарегистрированной SYSTEM-службой через SCM до передачи пароля. Есть ограничения размера и времени чтения/записи, четыре обработчика, bounded acknowledgement. Секреты не пишутся в аудит.

## Firewall и восстановление

Правило принадлежит приложению только при совпадении группы `RDPGuard.Managed`, строгого имени `RDPGuard.v1.TCP.NNNN` / `UDP.NNNN` и маркера описания. Одного префикса недостаточно для удаления. Коллизии с чужим правилом приводят к отказу. Направление только inbound, действие block, порт один; все адреса предварительно проходят нормализацию. До 4000 записей, партии до 200. Для каждой партии создаются два правила. Жёсткий предел — 20 партий / 40 правил; уменьшение размера партии требует соответствующего уменьшения общей ёмкости.

Изменённое собственное правило сначала удаляется; затем создаётся полностью ограниченное правило. Это может дать краткий промежуток сниженной защиты, но не расширяет блокировку. После COM-операций заново читается и сравнивается весь управляемый набор. Только после успешной проверки записи получают `applied`. Общий защищённый Windows mutex сериализует службу и emergency CLI.

Перед ACTIVE проверяются listener, совпадение RDP-порта в реестре, разрешающие правила по текущим профилям, работающий firewall, watchdog, whitelist текущего администратора, отсутствие пересечений и подписка Security. Требуется явное подтверждение резервного доступа. Персистентная lease появляется до ACTIVE; повторное подключение подтверждается LSM 21/25, проверенным через активную административную WTS-сессию (RDP protocol, токен, Session ID, пользователь/домен, время подключения). Время WTS должно быть строго после начала активации, время события — не раньше WTS и не в будущем, IP — в whitelist. Источник читается напрямую через Event Log API, поэтому подтверждение не ждёт SQLite-сборщика. После чтения повторно проверяется deadline. События 4624 любого типа, 4778 или 1149 без привязки к новому подключению недостаточны. Доказательство принятого подтверждения сохраняется в аудите.

Задача `RDPGuardRollback` запускается каждую минуту и при загрузке. Неподтверждённая активация или heartbeat старше 45 секунд приводят к постоянному emergency latch и удалению собственных правил. При штатном режиме служба проверяет deadline каждую секунду. При её отказе добавляется до примерно минуты задержки планировщика. Для повторной активации требуется полный preflight.

## Угрозы

| Угроза | Мера / граница |
|---|---|
| Перебор из интернета | Окно событий, порог, временные IP-блокировки RDP |
| 4625 от SMB ошибочно признан RDP | Тип 3 остаётся unconfirmed, выключен по умолчанию |
| Обычный пользователь RDS обращается к localhost | Отдельная аутентификация; база/pipe недоступны обычному SID |
| CSRF, DNS rebinding, XSS в имени пользователя | Origin, точный Host, CSRF в guard, CSP, Jinja autoescape, DOM textContent |
| Компрометация web-процесса | Нет shell/firewall/SQLite-доступа, ограниченный RPC; украденная сессия всё же позволяет административные действия в рамках проверенной политики |
| Подмена IPC-сервера | First-instance flag, непрерывный экземпляр, проверка PID/SCM, защищённые бинарники |
| Потеря RDP из-за ошибочного бана | Whitelist, WTS, narrow rules, preflight, emergency latch и watchdog |
| Массовые ложные срабатывания | Лимит новых блокировок и ёмкости; переход в Monitor Only |
| Падение службы / повреждение БД | Никакого нового блокирования при ошибке; watchdog и emergency независимы от SQLite |
| Локальный администратор / SYSTEM злоумышленник | Вне границы защиты: уже может менять firewall, службы, ACL и базу |

HTTP выбран только для numeric loopback. Cookie HttpOnly/SameSite Strict, без Secure из-за локального HTTP. Это не защищает от администратора машины, компрометированного браузера или процесса в той же пользовательской сессии. Публиковать порт через прокси запрещено.

## API-основания

- [Microsoft: 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Microsoft: bookmarks](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events)
- [Microsoft: INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)
- [Microsoft: named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [pywin32: EvtSubscribe](https://timgolden.me.uk/pywin32-docs/win32evtlog__EvtSubscribe_meth.html)

Перехвата пакетов, собственных сетевых драйверов и изменений Kaspersky нет.
