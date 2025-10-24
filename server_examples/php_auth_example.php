<?php
// new-solid-start/server_examples/php_auth_example.php
//
// Example PHP authentication endpoints using JWT stored in an HttpOnly cookie.
//
// Endpoints implemented (simple router based on REQUEST_URI & REQUEST_METHOD):
// - POST  /api/auth/login   -> accepts JSON { username, password }, verifies credentials,
//                             sets HttpOnly cookie "auth_token", returns user info.
// - GET   /api/auth/me      -> reads cookie, validates JWT, returns user info.
// - POST  /api/auth/logout  -> clears cookie (expires) and returns success.
//
// Notes & prerequisites:
// - This example uses firebase/php-jwt for JWT handling. Install via Composer:
//     composer require firebase/php-jwt
//   Then ensure your project autoloads vendor/autoload.php (this script assumes that).
// - For production:
//   - Use HTTPS and set 'secure' => true for cookies.
//   - Keep your JWT signing secret safe (env var, not checked into VCS).
//   - Implement token revocation / rotation if needed (refresh tokens).
//   - Add rate limiting, brute-force protections, logging, input validation, and CSRF protections as appropriate.
//
// This file is a minimal illustrative example and is NOT production-ready by itself.

require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// === Configuration ===
$JWT_SECRET = getenv('JWT_SECRET') ?: 'change-this-secret-to-a-strong-random-value';
$JWT_ALGO = 'HS256';
$JWT_EXP_SECONDS = 60 * 60; // 1 hour
$COOKIE_NAME = 'auth_token';

// In development without HTTPS, set to false. In production must be true.
$COOKIE_SECURE = false; // change to true when behind HTTPS
$COOKIE_SAMESITE = 'Lax'; // 'Strict'/'Lax'/'None' (None requires Secure)

// === Mock "database" of users ===
// In real app, replace with DB queries and passwords hashed with password_hash()
$users = [
    // password: demo123
    'demo' => [
        'id' => '1',
        'username' => 'demo',
        'password_hash' => password_hash('demo123', PASSWORD_DEFAULT),
        'name' => 'Demo User',
    ],
    // additional example
    'alice' => [
        'id' => '2',
        'username' => 'alice',
        'password_hash' => password_hash('alicepass', PASSWORD_DEFAULT),
        'name' => 'Alice',
    ],
];

// === Helpers ===
function jsonResponse($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function readJsonBody() {
    $raw = file_get_contents('php://input');
    if (!$raw) return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function setAuthCookie($name, $jwt, $expiresAt, $secure, $samesite) {
    // Use setcookie with options array (PHP 7.3+)
    $options = [
        'expires' => $expiresAt,
        'path' => '/',
        'domain' => '', // set if you want a specific domain
        'secure' => $secure,
        'httponly' => true,
        'samesite' => $samesite,
    ];
    setcookie($name, $jwt, $options);
}

function clearAuthCookie($name, $secure, $samesite) {
    // Set expiration in the past
    $options = [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => $samesite,
    ];
    setcookie($name, '', $options);
}

// Validate JWT from cookie, return decoded payload on success or null on failure.
function validateJwtFromCookie($cookieName, $secret, $algo) {
    if (empty($_COOKIE[$cookieName])) return null;
    $jwt = $_COOKIE[$cookieName];
    try {
        $decoded = JWT::decode($jwt, new Key($secret, $algo));
        // $decoded is an object. You can further validate claims if needed.
        return $decoded;
    } catch (Exception $e) {
        // token invalid/expired/other error
        return null;
    }
}

// === Simple router ===
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Normalize path if running under a subdirectory - adjust as needed.
// For this example we expect the script to be reachable so that REQUEST_URI matches /api/auth/...
// If using a front controller, you may need to adapt routing.

if ($path === '/api/auth/login' && $method === 'POST') {
    $body = readJsonBody();
    if (!$body || !isset($body['username']) || !isset($body['password'])) {
        jsonResponse(['error' => 'Missing credentials'], 400);
    }
    $username = (string)$body['username'];
    $password = (string)$body['password'];

    global $users, $JWT_SECRET, $JWT_EXP_SECONDS, $JWT_ALGO, $COOKIE_NAME, $COOKIE_SECURE, $COOKIE_SAMESITE;

    if (!isset($users[$username])) {
        jsonResponse(['error' => 'Invalid credentials'], 401);
    }

    $user = $users[$username];
    if (!password_verify($password, $user['password_hash'])) {
        jsonResponse(['error' => 'Invalid credentials'], 401);
    }

    // At this point credentials are valid. Create JWT.
    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + $JWT_EXP_SECONDS,
        'sub' => $user['id'],
        'username' => $user['username'],
        // Add any other claims you need (roles, scopes, etc.)
    ];

    $jwt = JWT::encode($payload, $JWT_SECRET, $JWT_ALGO);

    // Set HttpOnly cookie with JWT
    setAuthCookie($COOKIE_NAME, $jwt, $now + $JWT_EXP_SECONDS, $COOKIE_SECURE, $COOKIE_SAMESITE);

    // Return basic user info (do not include sensitive data)
    jsonResponse([
        'user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'name' => $user['name'],
        ],
    ], 200);
}

if ($path === '/api/auth/me' && $method === 'GET') {
    global $JWT_SECRET, $JWT_ALGO, $COOKIE_NAME, $users;

    $decoded = validateJwtFromCookie($COOKIE_NAME, $JWT_SECRET, $JWT_ALGO);
    if (!$decoded) {
        jsonResponse(['error' => 'Unauthenticated'], 401);
    }

    // decoded->sub should contain user id, decoded->username may be present
    $userId = property_exists($decoded, 'sub') ? (string)$decoded->sub : null;
    $usernameFromToken = property_exists($decoded, 'username') ? (string)$decoded->username : null;

    // Lookup user in DB by id or username
    $foundUser = null;
    if ($usernameFromToken && isset($users[$usernameFromToken])) {
        $foundUser = $users[$usernameFromToken];
    } else {
        // fallback: linear search by id (since our mock DB keyed by username)
        foreach ($users as $u) {
            if ((string)$u['id'] === $userId) {
                $foundUser = $u;
                break;
            }
        }
    }

    if (!$foundUser) {
        // User referenced by token no longer exists
        jsonResponse(['error' => 'Unauthenticated'], 401);
    }

    jsonResponse([
        'user' => [
            'id' => $foundUser['id'],
            'username' => $foundUser['username'],
            'name' => $foundUser['name'],
        ],
    ], 200);
}

if ($path === '/api/auth/logout' && $method === 'POST') {
    global $COOKIE_NAME, $COOKIE_SECURE, $COOKIE_SAMESITE;
    // Clear cookie
    clearAuthCookie($COOKIE_NAME, $COOKIE_SECURE, $COOKIE_SAMESITE);
    jsonResponse(['ok' => true]);
}

// Not found
http_response_code(404);
echo 'Not found';
