SET NAMES utf8mb4;

SET @db := DATABASE();

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'ALTER TABLE radacct ADD INDEX idx_acctstarttime (acctstarttime)',
    'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = @db AND table_name = 'radacct'
    AND column_name = 'acctstarttime'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'ALTER TABLE radacct ADD INDEX idx_acctstoptime (acctstoptime)',
    'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = @db AND table_name = 'radacct'
    AND column_name = 'acctstoptime'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'ALTER TABLE radacct ADD INDEX idx_radacct_username (username)',
    'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = @db AND table_name = 'radacct'
    AND column_name = 'username'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'ALTER TABLE radpostauth ADD INDEX idx_authdate (authdate)',
    'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = @db AND table_name = 'radpostauth'
    AND column_name = 'authdate'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql := (
  SELECT IF(COUNT(*) = 0,
    'ALTER TABLE radpostauth ADD INDEX idx_radpostauth_reply (reply)',
    'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = @db AND table_name = 'radpostauth'
    AND column_name = 'reply'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;