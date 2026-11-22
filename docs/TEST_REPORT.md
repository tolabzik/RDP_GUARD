# Отчёт о проверках

## Локальная проверка

В разработке выполнены автоматизированные unit/integration-тесты ядра, SQLite, API и безопасности панели на macOS / Python 3.13: **72 passed** на первом полном прогоне. Ruff и синтаксис обоих браузерных JavaScript-файлов проверены. Нативные Windows API на macOS не запускались.

Дополнительно проверены вход, dashboard, форма настроек, тёмная и светлая темы в браузере при узком и настольном viewport. Снимок находится в `docs/images/dashboard.jpg`, данные искусственные. Синтетическая локальная запись 1000 событий типа 3 в SQLite WAL с транзакционными bookmarks заняла около 0,18 секунды (5622 события/с); это измерение ядра на машине разработки, не доказательство end-to-end производительности Windows-сборщика.

Проверяются: порог, окно, дедупликация, повторно используемые Record ID, atomic bookmark, парсинг/NTSTATUS, тип 3 vs 10, whitelist и активные администраторы, недостоверная WTS-информация, TTL/эскалация, IPv4/mapped/IPv6, Monitor Only, circuit breaker, ошибки/read-back firewall, ownership, пустые списки, запрет wildcard, активация/откат/подтверждение, atomic import, безопасные параметры, Argon2id, CSRF, loopback, Origin/Host, session expiry/logout, login throttling, подмена RPC-идентичности и экспорт без секретов.

## Проверки GitHub Actions

Workflow `.github/workflows/ci.yml` запускает тесты на Python 3.12 / Linux и Windows Server 2022. Windows-тесты создают и проверяют узкие TCP/UDP firewall-правила с IPv4/IPv6 документационными адресами, затем снимают их и сравнивают исходный набор. Подписка и bookmark проверяются настоящим Windows Event Log API.

После PyInstaller сборки выполняется настоящая установка frozen-служб, login через LocalService → named pipe → SYSTEM, защищённая команда whitelist, проверка loopback listener, запрет ACTIVE при непрошедшем preflight и независимая emergency-команда после остановки служб. JUnit и журналы служб сохраняются в artifacts. Release публикуется только после успеха всех обязательных jobs.

Точный итог каждого прогона и commit доступны в [Actions](https://github.com/tolabzik/RDP_GUARD/actions). Если workflow не прошёл, выпуск не считается собранным/проверенным.

## Не выполнено в рамках разработки

Контролируемые реальные попытки RDP с отдельного внешнего IP, влияние на Kaspersky/SQL/1С, фактический throughput 1000 Windows-событий/минуту и end-to-end latency ≤5 секунд на целевом сервере, а также работа watchdog при реальной потере RDP. Эти пункты требуют отдельной [приёмки](ACCEPTANCE.md) с резервным доступом и разрешением владельца сервера.
