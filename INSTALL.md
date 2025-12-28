# Zero Trust NMS - Installation Guide

## Требования

### Минимальные системные требования
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Disk**: 50 GB SSD
- **OS**: Linux (Ubuntu 22.04+, RHEL 8+, Debian 12+)

### Программное обеспечение
- Docker 24.0+ и Docker Compose v2
- Go 1.22+ (для сборки из исходников)
- Git
- Make (опционально)

## Быстрый старт с Docker Compose

### 1. Клонирование репозитория

```bash
git clone https://github.com/zt-nms/zt-nms.git
cd zt-nms
```

### 2. Настройка окружения

```bash
# Копируем пример конфигурации
cd deployments/docker
cp .env.example .env

# Редактируем пароли (ОБЯЗАТЕЛЬНО для production!)
nano .env
```

**Важно**: Измените все пароли в `.env` файле:
```bash
POSTGRES_PASSWORD=your_strong_password_here
REDIS_PASSWORD=your_redis_password_here
GRAFANA_PASSWORD=your_grafana_password_here
```

### 3. Запуск системы

```bash
# Запуск всех сервисов
docker-compose up -d

# Проверка статуса
docker-compose ps

# Просмотр логов
docker-compose logs -f api-gateway
```

### 4. Инициализация базы данных

```bash
# Применение схемы базы данных
docker exec -i zt-nms-postgres psql -U ztnms ztnms < ../database/schema.sql
```

### 5. Проверка работоспособности

```bash
# Проверка health endpoint
curl -k https://localhost:8080/health

# Ожидаемый ответ:
# {"status":"healthy","timestamp":"...","version":"1.0.0"}
```

## Доступ к сервисам

После запуска доступны следующие сервисы:

| Сервис | URL | Описание |
|--------|-----|----------|
| API Gateway | https://localhost:8080 | Основной API |
| Metrics | http://localhost:9090 | Prometheus метрики |
| Grafana | http://localhost:3000 | Дашборды (admin/admin) |
| Jaeger | http://localhost:16686 | Трейсинг |
| PostgreSQL | localhost:5432 | База данных |
| Redis | localhost:6379 | Кэш |
| NATS | localhost:4222 | Очередь сообщений |

## Сборка из исходников

### 1. Установка зависимостей

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y git make golang-go

# Fedora/RHEL
sudo dnf install -y git make golang

# macOS
brew install go git make
```

### 2. Сборка

```bash
cd zt-nms

# Загрузка Go зависимостей
go mod download

# Сборка всех бинарников
make build

# Бинарники будут в директории bin/
ls -la bin/
# api-gateway
# zt-nms-cli
# zt-nms-agent
```

### 3. Локальный запуск

```bash
# Запуск только инфраструктуры (БД, Redis, NATS)
make dev

# Запуск API Gateway
make run-api

# Или напрямую
./bin/api-gateway
```

## Использование CLI

### Генерация ключей

```bash
# Генерация ключевой пары для оператора
./bin/zt-nms-cli keygen operator

# Результат:
# Generated key pair:
#   Private key: operator.key
#   Public key:  operator.pub
#   Public key (base64): <base64_encoded_key>
```

### Аутентификация

```bash
# Установка URL API
export ZTNMS_API_URL=https://localhost:8080

# Логин с использованием ключа
./bin/zt-nms-cli auth login --key operator.key
```

### Управление идентичностями

```bash
# Создание оператора
./bin/zt-nms-cli identity create \
  --type operator \
  --name admin \
  --email admin@example.com \
  --public-key operator.pub

# Список идентичностей
./bin/zt-nms-cli identity list

# Получение информации
./bin/zt-nms-cli identity get <identity_id>

# Приостановка
./bin/zt-nms-cli identity suspend <identity_id> --reason "Security review"
```

### Управление capabilities

```bash
# Запрос capability для устройства
./bin/zt-nms-cli capability request \
  --device <device_id> \
  --actions config.read,config.write \
  --duration 8h

# Список capability
./bin/zt-nms-cli capability list --subject <subject_id>

# Отзыв
./bin/zt-nms-cli capability revoke <capability_id> --reason "No longer needed"
```

### Управление устройствами

```bash
# Список устройств
./bin/zt-nms-cli device list

# Информация об устройстве
./bin/zt-nms-cli device get <device_id>

# Получение конфигурации
./bin/zt-nms-cli device config <device_id>

# Выполнение команды
./bin/zt-nms-cli device exec <device_id> "show running-config"
```

## Конфигурация

### Основной конфиг (configs/config.yaml)

```yaml
server:
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/zt-nms/tls/server.crt"
    key_file: "/etc/zt-nms/tls/server.key"

database:
  host: "postgres"
  port: 5432
  name: "ztnms"
  user: "ztnms"
  password: "${ZTNMS_DB_PASSWORD}"
  sslmode: "require"

capability:
  default_ttl: 8h
  max_ttl: 24h

attestation:
  enabled: true
  interval: 1h
```

### Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| ZTNMS_SERVER_PORT | Порт API сервера | 8080 |
| ZTNMS_DATABASE_HOST | Хост PostgreSQL | localhost |
| ZTNMS_DATABASE_PASSWORD | Пароль БД | - |
| ZTNMS_REDIS_HOST | Хост Redis | localhost |
| ZTNMS_REDIS_PASSWORD | Пароль Redis | - |
| ZTNMS_LOG_LEVEL | Уровень логирования | info |

## Production Deployment

### Kubernetes

```bash
# Создание namespace
kubectl create namespace zt-nms

# Создание secrets
kubectl create secret generic zt-nms-secrets \
  --from-literal=db-password='your_password' \
  --from-literal=redis-password='your_password' \
  -n zt-nms

# Применение манифестов
kubectl apply -f deployments/kubernetes/deployment.yaml

# Проверка
kubectl get pods -n zt-nms
```

### TLS сертификаты

```bash
# Генерация самоподписанного CA
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=ZT-NMS CA/O=ZT-NMS"

# Генерация серверного сертификата
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -out server.csr \
  -subj "/CN=api-gateway/O=ZT-NMS"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt
```

## Мониторинг

### Prometheus метрики

Доступны на `/metrics`:
- `ztnms_http_requests_total` - количество HTTP запросов
- `ztnms_http_request_duration_seconds` - время ответа
- `ztnms_authentications_total` - количество аутентификаций
- `ztnms_policy_evaluations_total` - количество оценок политик
- `ztnms_capabilities_issued_total` - выданные capabilities

### Grafana дашборды

1. Откройте http://localhost:3000
2. Логин: admin / admin
3. Импортируйте дашборды из `deployments/docker/monitoring/grafana/dashboards/`

## Troubleshooting

### Проблема: API не запускается

```bash
# Проверьте логи
docker-compose logs api-gateway

# Проверьте подключение к БД
docker exec -it zt-nms-postgres psql -U ztnms -d ztnms -c "SELECT 1"
```

### Проблема: Ошибка аутентификации

```bash
# Проверьте, что ключ правильный
./bin/zt-nms-cli keygen test
# Сравните public key с зарегистрированным
```

### Проблема: Нет связи с устройством

```bash
# Проверьте доступность устройства
ping <device_ip>
nc -zv <device_ip> 22

# Проверьте логи device-proxy
docker-compose logs device-proxy
```

### Сброс системы

```bash
# Полный сброс
docker-compose down -v
docker-compose up -d

# Переинициализация БД
docker exec -i zt-nms-postgres psql -U ztnms ztnms < ../database/schema.sql
```

## Остановка системы

```bash
# Остановка всех сервисов
cd deployments/docker
docker-compose down

# Остановка с удалением данных
docker-compose down -v
```

## Обновление

```bash
# Получение обновлений
git pull

# Пересборка образов
docker-compose build

# Перезапуск
docker-compose up -d
```

## Поддержка

- **Issues**: https://github.com/zt-nms/zt-nms/issues
- **Documentation**: https://docs.zt-nms.io
- **Email**: support@zt-nms.io
