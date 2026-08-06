# Config Auditor

CLI-утилита на Go для анализа JSON- и YAML-конфигураций веб-приложений и обнаружения потенциально опасных настроек.

## Возможности

Утилита обнаруживает:

| Rule ID | Уровень | Проверка |
|---|---:|---|
| CFG001 | LOW | Debug-логирование |
| CFG002 | HIGH | Пароль в открытом виде |
| CFG003 | MEDIUM | Прослушивание всех интерфейсов через `0.0.0.0` |
| CFG004 | HIGH | Отключённый TLS или проверка сертификатов |
| CFG005 | HIGH | Устаревшие и небезопасные алгоритмы |

Поддерживаемые форматы:

- JSON;
- YAML.

Поддерживаемые источники:

- Файл;
- Стандартный поток ввода.

## CLI

## Сборка

```bash
go build -o bin/config-auditor ./cmd/config-auditor
```

## Использование

Проверка файла:

```bash
./bin/config-auditor config.yaml
```

Проверка через стандартный поток ввода:

```bash
cat config.yaml | ./bin/config-auditor --stdin
```

Проверка строки:

```bash
echo '{"log":{"level":"debug"}}' |
  ./bin/config-auditor --stdin
```

## Флаги

```bash
-s, --silent
    Не возвращать ошибочный код завершения при найденных проблемах.

--stdin
    Прочитать конфигурацию из стандартного потока ввода.
```

## Пример

Конфигурация:

```yaml
log:
  level: debug

database:
  password: secret
```

Результат:

```bash
HIGH [CFG002] database.password
        Problem: Пароль в конфигурации хранится в открытом виде
        Recommendation: Удалите пароль из конфигурации и передавайте его через переменную окружения или менеджер секретов

LOW [CFG001] log.level
        Problem: Установлен debug уровень логирования
        Recommendation: Используйте уровень логирования info или выше

```

## Коды завершения:

| Код | Значение                                   |
| --: | ------------------------------------------ |
|   0 | Проблемы не найдены или включён `--silent` |
|   1 | Найдены потенциально опасные настройки     |
|   2 | Ошибка аргументов, чтения или парсинга     |


## HTTP API

Сборка HTTP-сервера:

```bash
go build -o bin/config-auditor-http ./cmd/config-auditor-http
```

Запуск:

```bash
./bin/config-auditor-http
```

По умолчанию сервер доступен по адресу:

```bash
http://127.0.0.1:8080
```

Проверка состояния:

```bash
curl http://127.0.0.1:8080/healthz
```

Анализ YAML:

```bash
curl \
  -X POST \
  -H 'Content-Type: application/yaml' \
  --data-binary @config.yaml \
  http://127.0.0.1:8080/v1/analyze
  ```

Анализ JSON:

```bash
curl \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-binary @config.json \
  http://127.0.0.1:8080/v1/analyze
```

Пример ответа:

```json
{
  "issues": [
    {
      "rule_id": "CFG001",
      "severity": "LOW",
      "path": "log.level",
      "message": "Установлен debug уровень логирования",
      "recommendation": "Используйте уровень логирования info или выше"
    }
  ],
  "count": 1
}
```

## Архитектура

```bash
cmd/config-auditor     CLI и обработка кодов завершения
internal/app           Сборка приложения и регистрация правил
internal/analyzer      Запуск правил и сортировка результатов
internal/configloader  Ограниченное чтение входных данных
internal/configutil    Рекурсивный обход конфигурации
internal/model         Модели результата
internal/parser        JSON/YAML-парсер
internal/rules         Независимые правила анализа
```

Каждое правило реализует интерфейс:

```Go
type Rule interface {
    ID() string
    Check(config map[string]any) []model.Issue
}
```

Для добавления новой проверки нужно:

1. Реализовать интерфейс Rule;
2. Покрыть правило тестами;
3. Зарегистрировать правило в internal/app.

## Тестирование

```bash
go test ./...
go test -race ./...
```

## Ограничения

Утилита выполняет статический анализ конфигурации и не определяет фактическую сетевую доступность приложения.

Привязка к 0.0.0.0 может быть допустимой при наличии firewall, reverse proxy или сетевых политик, поэтому она имеет уровень MEDIUM.

Ссылки на переменные окружения и менеджеры секретов не считаются паролями в открытом виде.