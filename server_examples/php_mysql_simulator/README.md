# PHP MySQL Simulator (file-based) — README

This directory contains a lightweight PHP simulator that mimics a MySQL-backed authentication API for development and testing purposes. It uses JSON files for storage and the PHP built-in web server for running the demo API.

> WARNING: This simulator is for local development and testing only. It omits many production security measures (CSRF protection, secure cookie flags for HTTPS, robust session management, rate limiting, input validation hardening, etc.). Do NOT use as-is in production.

## Location

Files:
- `index.php` — the simulator router and implementation (endpoints: `/api/auth/login`, `/api/auth/me`, `/api/auth/logout`)
- `users.json` — created automatically in the same folder when first run (stores demo user)
- `sessions.json` — created automatically to store sessions for the simulator

## Features

- Endpoints:
  - `POST /api/auth/login` — login with JSON body `{ "username": "...", "password": "..." }`. On success sets an HttpOnly cookie `auth_token` and returns user info.
  - `GET  /api/auth/me` — returns current user from session cookie, or `401` if unauthenticated.
  - `POST /api/auth/logout` — clears session cookie and session record.

- Session persistence is simulated using `sessions.json` (a simple token → user mapping).
- Default demo user is created on first run.

## Default demo credentials

- username: `demo`  
- password: `demo123`

## How to run (local machine with PHP)

1. Open a terminal and change into the simulator folder:

   ```
   cd path/to/new-solid-start/server_examples/php_mysql_simulator
   ```

2. Start the PHP built-in server:

   ```
   php -S 127.0.0.1:8000 index.php
   ```

   The simulator will now listen on `http://127.0.0.1:8000`.

3. Test the endpoints.

### Example: login (save cookies)

Use curl to send JSON credentials and save cookies:

```
curl -i -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"demo123"}' \
  -c cookies.txt
```

If successful, a cookie file `cookies.txt` will be created and the response contains the user JSON.

### Example: get current user

Use the saved cookie:

```
curl -i -X GET http://127.0.0.1:8000/api/auth/me \
  -b cookies.txt
```

### Example: logout

```
curl -i -X POST http://127.0.0.1:8000/api/auth/logout \
  -b cookies.txt
```

## If you don't have PHP installed

You can run the simulator quickly using the official PHP Docker image:

```
docker run --rm -it -p 8000:8000 -v "$(pwd)":/app -w /app php:8.1-cli php -S 0.0.0.0:8000 index.php
```

Adjust the `-v` path to point to the `php_mysql_simulator` directory in your project.

## How the simulator stores data

- `users.json` stores user records. The default demo user is automatically added on first run.
- `sessions.json` stores session tokens mapped to user IDs (used to validate the `auth_token` cookie).

You can edit `users.json` to add more users. To generate a password hash for a password value, you can run this PHP one-liner locally:

```
php -r "echo password_hash('yourpassword', PASSWORD_DEFAULT) . PHP_EOL;"
```

Then paste that hash as `password_hash` for a new user record in `users.json`.

Example user record:

```json
{
  "id": "abcd1234",
  "username": "alice",
  "password_hash": "$2y$10$...",
  "name": "Alice"
}
```

## CORS & origins

The simulator includes permissive CORS headers for local development. If you host your front-end on a different origin (port), ensure that the origin is allowed or update the CORS logic in `index.php`.

## Notes & limitations

- Session tokens are simple randomly generated hex tokens stored in `sessions.json`. They are NOT cryptographically designed for production use.
- Cookies are set with `HttpOnly` in the simulator but `secure` is `false` for local development. For production always set `secure => true` and serve over HTTPS.
- No CSRF protection is implemented. If you use cookie-based auth in a real app, implement CSRF defenses.
- No input sanitization or rate-limiting is provided — add them for realistic testing or production.

---

If you want, I can:
- Add a small helper script to create users programmatically.
- Provide a Docker Compose file that runs this simulator and a simple PHP environment.
- Replace the file-based simulation with a Dockerized MySQL + PHP sample app for a more realistic demo.

Tell me which you prefer and I will add it.