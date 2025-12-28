-- ZT-NMS: Create Admin User
-- Run this SQL to create admin/admin user
--
-- Via Docker:
--   docker exec -i zt-nms-postgres psql -U ztnms -d ztnms < create-admin-user.sql
--
-- Via psql:
--   PGPASSWORD=admin psql -h localhost -p 5432 -U ztnms -d ztnms < create-admin-user.sql

-- Create admin user (admin/admin)
INSERT INTO identities (
    id,
    type,
    status,
    public_key,
    attributes,
    created_at,
    updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000002',
    'operator',
    'active',
    decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=', 'base64'),
    '{
        "username": "admin",
        "email": "admin@zt-nms.local",
        "display_name": "Администратор",
        "role": "admin",
        "groups": ["admins", "network-ops"],
        "password_hash": "YWRtaW4="
    }'::jsonb,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO UPDATE SET
    attributes = EXCLUDED.attributes,
    status = 'active',
    updated_at = NOW();

-- Verify user was created
SELECT
    id,
    type,
    status,
    attributes->>'username' as username,
    attributes->>'role' as role,
    attributes->>'email' as email
FROM identities
WHERE attributes->>'username' = 'admin';
