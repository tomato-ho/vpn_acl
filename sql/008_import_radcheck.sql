SET NAMES utf8mb4;

-- 可选迁移：把已有 FreeRADIUS radcheck 里的密码导入 vpn_users.password_hash。
--
--   {PBKDF2-SHA256}100000$salt$hash  ->  pbkdf2-sha256$100000$salt$hash
--
-- 只在 radcheck 存在时执行；全新安装（没有 FreeRADIUS 表）可以跳过本文件。

SET @has_radcheck := (
  SELECT COUNT(*) FROM information_schema.tables
  WHERE table_schema = DATABASE() AND table_name = 'radcheck'
);

SET @sql := IF(@has_radcheck = 1,
  'UPDATE vpn_users u
     JOIN radcheck r
       ON r.username = u.username
      AND r.attribute = ''Password-With-Header''
      SET u.password_hash = CONCAT(
            ''pbkdf2-sha256$'',
            SUBSTRING(r.value, CHAR_LENGTH(''{PBKDF2-SHA256}'') + 1)),
          u.password_updated_at = NOW()
    WHERE u.password_hash = ''''
      AND r.value LIKE ''{PBKDF2-SHA256}%''',
  'DO 0');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT COUNT(*) AS migrated_users
FROM vpn_users
WHERE password_hash <> '';