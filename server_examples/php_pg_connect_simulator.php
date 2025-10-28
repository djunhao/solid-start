new-solid-start/server_examples/php_pg_connect_simulator.php#L1-400
<?php
// new-solid-start/server_examples/php_pg_connect_simulator.php
/**
 * PHP auth demo using the native pgsql extension (pg_connect) with file fallback.
 *
 * Endpoints:
 *   POST /api/auth/login   -> { username, password } (sets HttpOnly cookie 'auth_token')
 *   GET  /api/auth/me      -> returns { user } if authenticated
 *   POST /api/auth/logout  -> clears session
 *
 * Additionally:
 *   GET  /admin/migration.sql -> returns SQL migration for users and sessions tables
 *
 * Behavior:
 * - If Postgres connection info is provided via environment variables (DB_HOST, DB_NAME, DB_USER, DB_PASS),
 *   this script uses pg_connect() + parameterized queries and stores users/sessions in Postgres.
 * - Otherwise it falls back to file-based storage (users_pg_connect.json, sessions_pg_connect.json)
 *   using safe file locks.
 *
 * Security notes (demo only):
 * - Use HTTPS in production and set cookie 'secure' => true.
 * - Implement CSRF protection for cookie-based auth in production.
 * - Use rate limiting and robust input validation in production.
 *
 * Usage (built-in server for quick testing):
 *   php -S 127.0.0.1:8000 php_pg_connect_simulator.php
 *
 * Default demo credentials (file-fallback only):
 *   username: demo
 *   password: demo123
 */

declare(strict_types=1);

// -------------------------
// Basic CORS (for local dev)
// -------------------------
$allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? null;
if ($origin && in_array($origin, $allowed_origins, true)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: *"); // permissive for demo
}
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Accept");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

// -------------------------
// Config
// -------------------------
const COOKIE_NAME = 'auth_token';
const SESSION_TTL = 3600; // seconds

$DATA_DIR = __DIR__;
$USERS_FILE = $DATA_DIR . '/users_pg_connect.json';
$SESSIONS_FILE = $DATA_DIR . '/sessions_pg_connect.json';

// DB via env
$dbHost = getenv('DB_HOST') ?: null;
$dbName = getenv('DB_NAME') ?: null;
$dbUser = getenv('DB_USER') ?: null;
$dbPass = getenv('DB_PASS') ?: null;
$dbPort = getenv('DB_PORT') ?: null; // optional

// Cookie secure flag (default false for local dev); set env COOKIE_SECURE=1 in production
$cookieSecureEnv = getenv('COOKIE_SECURE');
$cookieSecure = $cookieSecureEnv !== false
    ? filter_var($cookieSecureEnv, FILTER_VALIDATE_BOOLEAN)
    : false;

// -------------------------
// Utilities
// -------------------------
function json_input(): ?array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return null;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function json_output($data, int $status = 200): void
{
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit();
}

// -------------------------
// File DB fallback helpers
// -------------------------
function file_read_json(string $path): array
{
    if (!file_exists($path)) {
        return [];
    }
    $fp = fopen($path, 'r');
    if (!$fp) {
        return [];
    }
    flock($fp, LOCK_SH);
    $contents = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($contents ?: '[]', true);
    return is_array($data) ? $data : [];
}

function file_write_json(string $path, $data): bool
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    $tmp = "$path.tmp";
    $fp = fopen($tmp, 'w');
    if (!$fp) {
        return false;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false;
    }
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    rename($tmp, $path);
    return true;
}

function ensure_demo_user_file(string $usersFile): void
{
    $users = file_read_json($usersFile);
    foreach ($users as $u) {
        if (isset($u['username']) && $u['username'] === 'demo') {
            return;
        }
    }
    $id = time() . bin2hex(random_bytes(4));
    $users[] = [
        'id' => (string) $id,
        'username' => 'demo',
        'password_hash' => password_hash('demo123', PASSWORD_DEFAULT),
        'name' => 'Demo User',
        'created_at' => date('c'),
    ];
    file_write_json($usersFile, $users);
}

function file_find_user_by_username(string $usersFile, string $username): ?array
{
    $users = file_read_json($usersFile);
    foreach ($users as $u) {
        if (isset($u['username']) && $u['username'] === $username) {
            return $u;
        }
    }
    return null;
}

function file_find_user_by_id(string $usersFile, $id): ?array
{
    $users = file_read_json($usersFile);
    foreach ($users as $u) {
        if (isset($u['id']) && (string)$u['id'] === (string)$id) {
            return $u;
        }
    }
    return null;
}

function file_create_session(string $sessionsFile, string $userId): string
{
    $sessions = file_read_json($sessionsFile);
    $token = bin2hex(random_bytes(32));
    $sessions[$token] = [
        'userId' => (string)$userId,
        'created_at' => time(),
        'expires_at' => time() + SESSION_TTL,
    ];
    file_write_json($sessionsFile, $sessions);
    return $token;
}

function file_get_user_from_cookie(string $sessionsFile, string $usersFile): ?array
{
    if (empty($_COOKIE[COOKIE_NAME])) {
        return null;
    }
    $token = $_COOKIE[COOKIE_NAME];
    $sessions = file_read_json($sessionsFile);
    if (empty($sessions[$token])) {
        return null;
    }
    $sess = $sessions[$token];
    if (isset($sess['expires_at']) && $sess['expires_at'] < time()) {
        return null;
    }
    return file_find_user_by_id($usersFile, $sess['userId']);
}

function file_delete_session_cookie(string $sessionsFile): void
{
    if (empty($_COOKIE[COOKIE_NAME])) {
        return;
    }
    $token = $_COOKIE[COOKIE_NAME];
    $sessions = file_read_json($sessionsFile);
    if (isset($sessions[$token])) {
        unset($sessions[$token]);
        file_write_json($sessionsFile, $sessions);
    }
    setcookie(COOKIE_NAME, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'httponly' => true,
        'secure' => $GLOBALS['cookieSecure'],
        'samesite' => 'Lax',
    ]);
}

// -------------------------
// pg_connect helpers
// -------------------------
function get_pg_conn()
{
    global $dbHost, $dbName, $dbUser, $dbPass, $dbPort;
    if (!$dbHost || !$dbName || !$dbUser) {
        return null;
    }
    $parts = [];
    $parts[] = "host={$dbHost}";
    if ($dbPort) {
        $parts[] = "port={$dbPort}";
    }
    $parts[] = "dbname={$dbName}";
    $parts[] = "user={$dbUser}";
    if ($dbPass) {
        $parts[] = "password={$dbPass}";
    }
    $connStr = implode(' ', $parts);
    $conn = @pg_connect($connStr);
    if ($conn === false) {
        error_log("pg_connect failed: {$connStr}");
        return null;
    }
    return $conn;
}

function pg_find_user_by_username($conn, string $username): ?array
{
    $res = @pg_query_params($conn, 'SELECT id, username, password_hash, name FROM users WHERE username = $1 LIMIT 1', [$username]);
    if (!$res) return null;
    $row = pg_fetch_assoc($res);
    if (!$row) return null;
    $row['id'] = (string)$row['id'];
    return $row;
}

function pg_find_user_by_id($conn, $id): ?array
{
    $res = @pg_query_params($conn, 'SELECT id, username, name FROM users WHERE id = $1 LIMIT 1', [$id]);
    if (!$res) return null;
    $row = pg_fetch_assoc($res);
    if (!$row) return null;
    $row['id'] = (string)$row['id'];
    return $row;
}

function pg_create_session($conn, string $userId): string
{
    $token = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', time() + SESSION_TTL);
    $res = @pg_query_params($conn, 'INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)', [$token, $userId, $expiresAt]);
    if ($res === false) {
        error_log('pg_create_session failed: ' . pg_last_error($conn));
    }
    return $token;
}

function pg_get_user_from_cookie($conn): ?array
{
    if (empty($_COOKIE[COOKIE_NAME])) {
        return null;
    }
    $token = $_COOKIE[COOKIE_NAME];
    $res = @pg_query_params($conn, 'SELECT user_id FROM sessions WHERE token = $1 AND expires_at > now() LIMIT 1', [$token]);
    if (!$res) return null;
    $row = pg_fetch_assoc($res);
    if (!$row) return null;
    return pg_find_user_by_id($conn, $row['user_id']);
}

function pg_delete_session_cookie($conn): void
{
    if (empty($_COOKIE[COOKIE_NAME])) {
        return;
    }
    $token = $_COOKIE[COOKIE_NAME];
    $res = @pg_query_params($conn, 'DELETE FROM sessions WHERE token = $1', [$token]);
    if ($res === false) {
        error_log('pg_delete_session_cookie failed: ' . pg_last_error($conn));
    }
    setcookie(COOKIE_NAME, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'httponly' => true,
        'secure' => $GLOBALS['cookieSecure'],
        'samesite' => 'Lax',
    ]);
}

// -------------------------
// Initialization
// -------------------------
$conn = get_pg_conn();
$usePg = $conn !== null;

if (!$usePg) {
    // ensure demo user exists in file fallback
    ensure_demo_user_file($USERS_FILE);
}

// -------------------------
// Migrations endpoint content (returned by /admin/migration.sql)
// -------------------------
$migration_sql = <<<SQL
-- users table
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(191) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- sessions table
CREATE TABLE sessions (
  token CHAR(64) PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX ON sessions (user_id);
SQL;

// -------------------------
// Router
// -------------------------
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

// Serve static files when using PHP built-in server
if (php_sapi_name() === 'cli-server') {
    $file = __DIR__ . $path;
    if ($file !== __FILE__ && file_exists($file) && is_file($file)) {
        return false;
    }
}

// Admin: return migration SQL (restrict to local requests for safety)
if ($path === '/admin/migration.sql' && $method === 'GET') {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (in_array($remote, ['127.0.0.1', '::1'], true) || php_sapi_name() === 'cli') {
        header('Content-Type: text/sql; charset=utf-8');
        echo $migration_sql;
        exit();
    } else {
        http_response_code(403);
        echo 'Forbidden';
        exit();
    }
}

// ----- AUTH: login, me, logout -----
if ($path === '/api/auth/login' && $method === 'POST') {
    $body = json_input();
    if (!$body || !isset($body['username']) || !isset($body['password'])) {
        json_output(['error' => 'Missing username or password'], 400);
    }
    $username = (string)$body['username'];
    $password = (string)$body['password'];

    if ($usePg) {
        $user = pg_find_user_by_username($conn, $username);
        if (!$user || !isset($user['password_hash']) || !password_verify($password, $user['password_hash'])) {
            json_output(['error' => 'Invalid credentials'], 401);
        }
        $token = pg_create_session($conn, $user['id']);
        setcookie(COOKIE_NAME, $token, [
            'expires' => time() + SESSION_TTL,
            'path' => '/',
            'httponly' => true,
            'secure' => $cookieSecure,
            'samesite' => 'Lax',
        ]);
        json_output([
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
            ],
        ]);
    } else {
        $user = file_find_user_by_username($USERS_FILE, $username);
        if (!$user || !isset($user['password_hash']) || !password_verify($password, $user['password_hash'])) {
            json_output(['error' => 'Invalid credentials'], 401);
        }
        $token = file_create_session($SESSIONS_FILE, $user['id']);
        setcookie(COOKIE_NAME, $token, [
            'expires' => time() + SESSION_TTL,
            'path' => '/',
            'httponly' => true,
            'secure' => $cookieSecure,
            'samesite' => 'Lax',
        ]);
        json_output([
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
            ],
        ]);
    }
}

if ($path === '/api/auth/me' && $method === 'GET') {
    if ($usePg) {
        $user = pg_get_user_from_cookie($conn);
        if (!$user) {
            json_output(['error' => 'Unauthenticated'], 401);
        }
        json_output(['user' => $user]);
    } else {
        $user = file_get_user_from_cookie($SESSIONS_FILE, $USERS_FILE);
        if (!$user) {
            json_output(['error' => 'Unauthenticated'], 401);
        }
        json_output([
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
            ],
        ]);
    }
}

if ($path === '/api/auth/logout' && $method === 'POST') {
    if ($usePg) {
        pg_delete_session_cookie($conn);
    } else {
        file_delete_session_cookie($SESSIONS_FILE);
    }
    json_output(['ok' => true]);
}

// Not found
json_output(['error' => 'Not Found'], 404);
?>
