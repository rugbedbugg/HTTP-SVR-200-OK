# Contributing to HTTP-SVR-200-OK

Thanks for helping improve the server. Keep changes focused and preserve its freestanding, no-libc design.

## Development setup

Install GCC and the standard Linux development tools. Build from the repository root:

```sh
./build.sh http-server
```

The equivalent compiler invocation is documented in `README.md`. Keep assembly in NASM/GAS-compatible source files under `src/` and C helpers limited to the existing freestanding interface.

## Verification

There is no automated suite yet. Start the server, then exercise registration, login, authenticated file listing, and representative error responses with the `curl` commands in the README. Confirm response status, `Content-Length`, and session-cookie behavior before submitting.

## Pull requests

- Explain the request-path or syscall behavior being changed.
- Keep routing, parsing, authentication, and response-building concerns in their existing modules.
- Add a reproducible manual check for fixes and new endpoints.
- Do not introduce libc or runtime dependencies without first discussing the architectural change.
- Avoid committing the built `http-server` binary or local runtime data.
