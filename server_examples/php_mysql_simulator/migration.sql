-- new-solid-start/server_examples/php_mysql_simulator/migration.sql
-- SQL migration to create `users` and `sessions` tables for MySQL (InnoDB, utf8mb4)
-- Run this once against your database to prepare tables used by the demo app.
-- Example:
--   mysql -u root -p your_database < migration.sql
--
-- NOTE: Replace placeholders where indicated. To generate a PHP password hash, run:
--   php -r "echo password_hash('demo123', PASSWORD_DEFAULT).PHP_EOL;"

SET FOREIGN_KEY_CHECKS = 0;

-- Drop existing tables if you want a fresh start (optional)
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- Users table
CREATE TABLE IF NOT EXISTS `users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(191) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_users_username` (`username`),
  INDEX `idx_users_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions table: stores session tokens (e.g. random token keys)
CREATE TABLE IF NOT EXISTS `sessions` (
  `token` CHAR(64) NOT NULL,                      -- store hex(32) token (64 chars)
  `user_id` BIGINT UNSIGNED NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` TIMESTAMP NOT NULL,
  PRIMARY KEY (`token`),
  INDEX `idx_sessions_user_id` (`user_id`),
  INDEX `idx_sessions_expires_at` (`expires_at`),
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional: cleanup helper (MySQL event or cron job recommended)
-- Example SQL to delete expired sessions:
-- DELETE FROM sessions WHERE expires_at < NOW();

-- Optional: insert a demo user (only if you want a seeded account).
-- WARNING: Replace '<PASSWORD_HASH>' with the output from PHP's password_hash().
-- Example to generate hash: php -r "echo password_hash('demo123', PASSWORD_DEFAULT).PHP_EOL;"
--
-- INSERT INTO users (username, password_hash, name, email)
-- VALUES ('demo', '<PASSWORD_HASH>', 'Demo User', 'demo@example.com');

-- End of migration
