SET NAMES utf8mb4;

UPDATE radpostauth SET pass = '';

DROP TRIGGER IF EXISTS radpostauth_clear_pass;
CREATE TRIGGER radpostauth_clear_pass
BEFORE INSERT ON radpostauth
FOR EACH ROW SET NEW.pass = '';