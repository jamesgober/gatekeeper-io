# gatekeeper-io performance

Measured 2026-11-08 with criterion (`cargo bench`), Rust 1.99, release
profile, Windows 11 x86-64 on a shared development machine (other builds
were running). Median, with criterion's 95% interval. Treat them as
build-to-build comparisons, not reference-box numbers.

| Benchmark | Time | What it measures |
|---|---|---|
| `gates/authenticate_member` | 989 ns (954 to 1030) | cookie parse, auth-gate's request path, subject unpacked from the payload |
| `gates/authenticate_guest` | 24.9 ns (24.1 to 26.0) | no cookie |
| `gates/authorize` | 79.2 ns (74.5 to 84.7) | the router check (includes cloning the stage in the benchmark) |
| `gates/both` | 1.05 us (1.02 to 1.09) | both gates for a signed-in request |
| `gates/csrf_check` | 50.7 ns (49.2 to 52.3) | a signed-in form's CSRF token and origin facts |

Both gates together cost about a microsecond on a signed-in request, with
no database read. The estimate this design started from (55 to 105 ns)
counted only a session lookup and a permission test; the measured path
also verifies the token's signature, hashes it into the lookup key, and
hashes the client binding on every request. Those are deliberate, and the
tuning candidates are listed in auth-gate's `docs/PERFORMANCE.md`.

Run with `cargo bench --bench gates`.

## Re-measured 2026-11-11 (0.5.0, same shared machine, busier)

| Benchmark | 0.4 | 0.5 |
|---|---|---|
| `gates/both` | 1.05 us | 744 ns (709 to 784) |
| `gates/authorize` | 79 ns | 37.8 ns (37.3 to 38.3) |

The browser binding hash now runs only when the network prefix moves or at
the touch interval, and `check` reads the clock only for rules or standings
that need it.
