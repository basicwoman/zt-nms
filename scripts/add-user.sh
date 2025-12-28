#!/bin/bash
# ZT-NMS User Management Script
# Usage: ./add-user.sh [username] [password] [role]
# Example: ./add-user.sh admin admin admin
#          ./add-user.sh operator1 secret123 operator

set -e

# Default values
USERNAME="${1:-admin}"
PASSWORD="${2:-admin}"
ROLE="${3:-admin}"
EMAIL="${USERNAME}@zt-nms.local"
DISPLAY_NAME="${USERNAME^}"  # Capitalize first letter

# Database connection (adjust if needed)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-ztnms}"
DB_USER="${DB_USER:-ztnms}"
DB_PASSWORD="${DB_PASSWORD:-admin}"

# Generate UUID for identity
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen || python3 -c "import uuid; print(uuid.uuid4())")

# Hash password using SHA-256 (in production use bcrypt/argon2)
# For simplicity, storing as plaintext base64 - the app validates against this
PASSWORD_HASH=$(echo -n "${PASSWORD}" | base64)

echo "================================================"
echo "ZT-NMS User Management"
echo "================================================"
echo "Username:     ${USERNAME}"
echo "Email:        ${EMAIL}"
echo "Role:         ${ROLE}"
echo "Display Name: ${DISPLAY_NAME}"
echo "UUID:         ${UUID}"
echo "================================================"

# SQL to insert user
SQL="
INSERT INTO identities (
    id,
    type,
    status,
    public_key,
    attributes,
    created_at,
    updated_at
) VALUES (
    '${UUID}',
    'operator',
    'active',
    decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=', 'base64'),
    jsonb_build_object(
        'username', '${USERNAME}',
        'email', '${EMAIL}',
        'display_name', '${DISPLAY_NAME}',
        'role', '${ROLE}',
        'groups', jsonb_build_array('${ROLE}s', 'network-ops'),
        'password_hash', '${PASSWORD_HASH}'
    ),
    NOW(),
    NOW()
)
ON CONFLICT (id) DO UPDATE SET
    attributes = EXCLUDED.attributes,
    updated_at = NOW();
"

echo ""
echo "Executing SQL..."
echo ""

# Check if running inside Docker or directly
if command -v docker &> /dev/null && docker ps --format '{{.Names}}' | grep -q "zt-nms-postgres"; then
    echo "Using Docker container 'zt-nms-postgres'..."
    docker exec -i zt-nms-postgres psql -U "${DB_USER}" -d "${DB_NAME}" -c "${SQL}"
elif command -v psql &> /dev/null; then
    echo "Using local psql..."
    PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "${SQL}"
else
    echo "ERROR: Neither Docker nor psql found!"
    echo ""
    echo "To add user manually, run this SQL in your PostgreSQL:"
    echo ""
    echo "${SQL}"
    exit 1
fi

echo ""
echo "================================================"
echo "User '${USERNAME}' created/updated successfully!"
echo ""
echo "Login credentials:"
echo "  Username: ${USERNAME}"
echo "  Password: ${PASSWORD}"
echo "================================================"
