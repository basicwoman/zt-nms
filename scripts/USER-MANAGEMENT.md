# ZT-NMS User Management

## Структура данных

Пользователи хранятся в таблице `identities` в PostgreSQL:

```sql
SELECT id, type, status, attributes->>'username' as username
FROM identities WHERE type = 'operator';
```

## Добавление пользователя admin/admin

### Способ 1: SQL файл (рекомендуется)

```bash
# Запустить контейнеры
docker-compose -f deployments/docker/docker-compose.yml up -d

# Выполнить SQL
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms < scripts/create-admin-user.sql
```

### Способ 2: Bash скрипт

```bash
# Добавить admin/admin
./scripts/add-user.sh admin admin admin

# Добавить оператора
./scripts/add-user.sh operator1 secret123 operator

# Добавить read-only пользователя
./scripts/add-user.sh viewer mypass123 viewer
```

### Способ 3: Прямой SQL запрос

```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
INSERT INTO identities (id, type, status, public_key, attributes, created_at, updated_at)
VALUES (
    '$(uuidgen)',
    'operator',
    'active',
    decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=', 'base64'),
    '{
        \"username\": \"myuser\",
        \"email\": \"myuser@example.com\",
        \"display_name\": \"My User\",
        \"role\": \"admin\",
        \"groups\": [\"admins\"],
        \"password_hash\": \"$(echo -n 'mypassword' | base64)\"
    }'::jsonb,
    NOW(),
    NOW()
);
"
```

## Роли пользователей

| Роль | Описание |
|------|----------|
| `admin` | Полный доступ ко всем функциям |
| `operator` | Управление устройствами и конфигурациями |
| `viewer` | Только просмотр |
| `auditor` | Доступ к аудит логам |

## Полезные команды

### Список всех пользователей

```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
SELECT
    id,
    status,
    attributes->>'username' as username,
    attributes->>'email' as email,
    attributes->>'role' as role,
    created_at
FROM identities
WHERE type = 'operator'
ORDER BY created_at;
"
```

### Изменить пароль пользователя

```bash
# Новый пароль в base64
NEW_PASSWORD=$(echo -n 'newpassword123' | base64)

docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
UPDATE identities
SET attributes = jsonb_set(attributes, '{password_hash}', '\"${NEW_PASSWORD}\"'),
    updated_at = NOW()
WHERE attributes->>'username' = 'admin';
"
```

### Заблокировать пользователя

```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
UPDATE identities
SET status = 'suspended', updated_at = NOW()
WHERE attributes->>'username' = 'baduser';
"
```

### Удалить пользователя

```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
DELETE FROM identities
WHERE attributes->>'username' = 'olduser' AND type = 'operator';
"
```

### Разблокировать пользователя

```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
UPDATE identities
SET status = 'active', updated_at = NOW()
WHERE attributes->>'username' = 'blockeduser';
"
```

## Дефолтные пользователи (из seed данных)

При первом запуске создаются:

| Username | Password | Role | Описание |
|----------|----------|------|----------|
| `admin` | `admin` | admin | Администратор системы |
| `operator1` | `operator1` | operator | Оператор сети |
| `auditor1` | `auditor1` | auditor | Аудитор |

## Проверка входа через API

```bash
# Получить токен
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Ответ:
# {"access_token":"...","token_type":"Bearer","expires_in":3600,...}
```

## Troubleshooting

### Пользователь не может войти

1. Проверьте что пользователь существует:
```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
SELECT attributes->>'username', status FROM identities WHERE attributes->>'username' = 'admin';
"
```

2. Проверьте статус (должен быть `active`):
```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
UPDATE identities SET status = 'active' WHERE attributes->>'username' = 'admin';
"
```

3. Сбросьте пароль на `admin`:
```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms -c "
UPDATE identities
SET attributes = jsonb_set(attributes, '{password_hash}', '\"YWRtaW4=\"')
WHERE attributes->>'username' = 'admin';
"
```

### База данных пустая

Выполните seed данные:
```bash
docker exec -i zt-nms-postgres psql -U ztnms -d ztnms < deployments/database/02-seed.sql
```
