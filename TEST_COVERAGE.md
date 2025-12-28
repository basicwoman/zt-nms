# ZT-NMS Test Coverage Report

**Дата:** 2025-12-27
**Всего тестов:** 348
**Прошло:** 100%

## Результаты тестирования

| Модуль | Кол-во тестов | Прошло | Покрытие | Время |
|--------|---------------|--------|----------|-------|
| pkg/crypto | 30 | 30 | 88.6% | 2.544s |
| internal/config | 28 | 28 | 81.1% | 0.873s |
| internal/analytics | 35 | 35 | 66.3% | 0.753s |
| internal/policy | 15 | 15 | 43.7% | 2.175s |
| pkg/models | 16 | 16 | 42.8% | 2.709s |
| internal/attestation | 32 | 32 | 39.5% | 1.804s |
| internal/audit | 34 | 34 | 38.2% | 1.988s |
| internal/identity | 27 | 27 | 36.6% | 1.621s |
| internal/inventory | 41 | 41 | 33.3% | 2.357s |
| internal/capability | 11 | 11 | 28.2% | 1.433s |
| internal/api | 54 | 54 | 26.0% | 1.065s |
| internal/proxy | 25 | 25 | 10.8% | 1.248s |
| **ИТОГО** | **348** | **348** | - | **20.57s** |

## Улучшения покрытия

| Модуль | До | После | Улучшение |
|--------|-----|-------|-----------|
| internal/analytics | 0.0% | 66.3% | +66.3% |
| internal/inventory | 0.0% | 33.3% | +33.3% |
| internal/proxy | 0.0% | 10.8% | +10.8% |

## Тестовая база данных

```bash
# Параметры подключения
Host: localhost
Port: 5433
User: ztnms
Password: ztnms_test
Database: ztnms_test

# Запуск тестовой БД
docker run -d \
  --name zt-nms-test-db \
  -e POSTGRES_USER=ztnms \
  -e POSTGRES_PASSWORD=ztnms_test \
  -e POSTGRES_DB=ztnms_test \
  -p 5433:5432 \
  postgres:15-alpine

# Загрузка схемы
docker exec -i zt-nms-test-db psql -U ztnms -d ztnms_test < deployments/database/schema.sql
docker exec -i zt-nms-test-db psql -U ztnms -d ztnms_test < deployments/database/02-seed.sql
```

## Запуск тестов

```bash
# Все тесты с покрытием
go test ./... -v -cover

# Без кэша (реальное время)
go test ./... -cover -count=1

# Конкретный пакет
go test -v -cover ./internal/analytics/...
```
