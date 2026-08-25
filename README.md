# HTTP-SVR-200-OK

![GitHub last commit](https://img.shields.io/github/last-commit/rugbedbugg/HTTP-SVR-200-OK?style=for-the-badge&labelColor=000000)
![GitHub repo size](https://img.shields.io/github/repo-size/rugbedbugg/HTTP-SVR-200-OK?style=for-the-badge&labelColor=000000)
![Stars](https://img.shields.io/github/stars/rugbedbugg/HTTP-SVR-200-OK?style=for-the-badge&labelColor=000000)

A bare-metal x86-64 Linux HTTP/1.1 server written entirely in assembly (NASM syntax via GCC). Implements a single-threaded event loop with `epoll`-style accept/read/close via raw syscalls. Features: GET/POST routing, session-based authentication (SHA-256 salted password hashes, constant-time comparisons), authenticated `/files` directory listing with dynamic `Content-Length`, and 5-second receive timeout to bound slow-client stalls.

## Status

**Active** - core HTTP server + auth + file serving complete.

## Features

| Feature | Description |
|---------|-------------|
| Pure assembly | NASM syntax, GCC-linked, no libc (`-nostdlib -ffreestanding`) |
| Raw syscalls only | `socket`, `bind`, `listen`, `accept`, `read`, `write`, `close`, `setsockopt`, `exit` |
| Single-threaded | One client at a time, sequential processing |
| HTTP/1.1 subset | GET, POST, headers, `Content-Length` (no chunked) |
| Routing | `/`, `/register`, `/login`, `/logout`, `/files` (auth required) |
| Session auth | SHA-256 salted hashes via `getrandom(2)`, 96-byte slots |
| Timing-safe | Constant-time compare for passwords, usernames, tokens |
| Slow-client bound | `SO_RCVTIMEO` 5s |
| Auth `/files` | Dynamic `Content-Length` directory listing |

## Tech Stack

| Component | Details |
|-----------|---------|
| Language | x86-64 Assembly (NASM via `.intel_syntax noprefix`) |
| Toolchain | GCC (assembler + linker) - `-nostdlib -no-pie -ffreestanding` |
| Syscalls | Linux x86-64 ABI: `socket(41)`, `bind(49)`, `listen(50)`, `accept(43)`, `read(0)`, `write(1)`, `close(3)`, `setsockopt(54)`, `exit(60)`, `getrandom(318)` |
| Crypto | SHA-256 in C (`sha256.c`) for password hashing |

## Architecture

### Module Map (`src/`)

| File | Responsibility |
|------|----------------|
| `server.s` | Main loop: socket → bind → listen → accept → setsockopt(RCVTIMEO) → read → parse → route → close → loop |
| `routing.s` | Method (GET/POST) + path dispatch → handlers |
| `responses.s` | HTTP response builders (200, 400, 401, 403, 404, 405, 500) |
| `helpers.s` | String utils, header parsing (`FIND_HDR_END`, `PARSE_CONTENT_LENGTH`) |
| `users.s` | User table (fixed 96-byte slots), registration, lookup |
| `session.s` | Session tokens (random), validation, expiry |
| `files.s` | `/files` handler: `opendir`/`readdir` via syscalls, dynamic `Content-Length` |
| `sha256.c` | SHA-256 implementation (C, called from assembly) |

### Request Flow

1. **Accept** - `accept()` client FD, set `SO_RCVTIMEO=5s`
2. **Read** - `read()` up to 4096 bytes into `REQ_BUF`
3. **Parse Method** - Match `GET ` or `POST `, extract path pointer, set method ID
4. **Header Boundary** - `FIND_HDR_END` locates `\r\n\r\n`
5. **Content-Length** - `PARSE_CONTENT_LENGTH` extracts `Content-Length` (POST body validation)
6. **Route** - `ROUTE` dispatches to handler based on method + path
7. **Respond** - Handler builds response via `responses.s`, `write()` to client FD
8. **Close** - `close()` client FD, loop to `ACCEPT`

## Install / Build

### Prerequisites

| Requirement | Details |
|-------------|---------|
| GCC | For assembling/linking assembly + C |
| Linux | x86-64, raw syscalls |
| make | Optional (single script build) |

### Build

```bash
./build.sh http-server
# or manually:
gcc -nostdlib -no-pie -ffreestanding -fno-builtin -fno-stack-protector -o http-server src/*.s src/*.c
```

### Run

```bash
./http-server
# Listens on 0.0.0.0:8080
```

Place static files in `files_root/` for `/files` endpoint.

## Commands / Usage

The server has no CLI flags - it binds to port 8080 and runs forever:

```bash
./http-server &
curl http://localhost:8080/
curl -X POST http://localhost:8080/register -d "user=alice&pass=secret"
curl -X POST http://localhost:8080/login -d "user=alice&pass=secret"
curl -H "Cookie: session=<token>" http://localhost:8080/files
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | No | Index page |
| POST | `/register` | No | Create account (user + pass) |
| POST | `/login` | No | Start session, returns `Set-Cookie: session=...` |
| POST | `/logout` | Yes | Invalidate session |
| GET | `/files` | Yes | Directory listing of `files_root/` with `Content-Length` |

## Options / Configuration

Constants in assembly (modify `server.s`/`routing.s` and rebuild):

| Constant | Value | Description |
|----------|-------|-------------|
| Port | `8080` | `sin_port = 0x901f` in `server.s` |
| Backlog | `4096` | `listen()` backlog |
| Recv Timeout | `5s` | `SO_RCVTIMEO` tv_sec |
| Request Buffer | `4096` | `read()` max bytes |
| User Slot Size | `96B` | Fixed per-user record |

## Project Structure

```
HTTP-SVR-200-OK/
├── src/
│   ├── server.s          # Main loop, socket setup, accept/read/close
│   ├── routing.s         # Method + path dispatch
│   ├── responses.s       # HTTP response builders
│   ├── helpers.s         # Header parsing, string utils
│   ├── users.s           # User table, registration, lookup
│   ├── session.s         # Session tokens, validation
│   ├── files.s           # /files handler (auth + dir listing)
│   └── sha256.c          # SHA-256 (C, called from asm)
├── files_root/           # Static files served at /files (gitignored except .keep)
├── tests/
│   ├── filedump.c        # Debug: dump files_root contents
│   └── saltdump.c        # Debug: dump user table salts
├── build.sh              # One-line GCC build
├── server                # Built binary (gitignored)
├── .gitignore
└── README.md
```

## Testing

No automated test suite. Manual verification:

```bash
./build.sh http-server
./http-server &
# In another terminal:
curl -v http://localhost:8080/
curl -v -X POST http://localhost:8080/register -d "user=test&pass=pass123"
curl -v -X POST http://localhost:8080/login -d "user=test&pass=pass123"
# Copy session cookie from Set-Cookie header
curl -v -H "Cookie: session=<token>" http://localhost:8080/files
# Should list files_root/ contents with Content-Length
```

## Notes / Gotchas

| Note | Details |
|------|---------|
| No libc | All syscalls inline, no `printf`, `malloc`, `pthread`, etc. |
| Single-threaded | One request at a time; slow clients blocked by `SO_RCVTIMEO` |
| Fixed user table | 96-byte slots, no dynamic allocation (no heap) |
| Session tokens | Random bytes via `getrandom(2)`, constant-time compare on validate |
| Password hashing | SHA-256(salt + password), salt from `getrandom(2)` |
| Port 8080 | Requires no root; change in `server.s` for port 80 |
| Linux-only | Syscall numbers and ABI are x86-64 Linux specific |

## License

MIT, see [LICENSE](LICENSE).

## Links

- **Repo:** https://github.com/rugbedbugg/HTTP-SVR-200-OK
- **Issues:** https://github.com/rugbedbugg/HTTP-SVR-200-OK/issues