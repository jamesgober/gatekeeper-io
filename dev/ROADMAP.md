# gatekeeper-io: Roadmap

| Version | Status | Scope |
|---|---|---|
| 0.1.0 | done | core types, the main path, in-memory stores, unit and integration tests |
| 0.2.0 | done | design lock: API settled with the server and router crates, docs, examples |
| 0.3.0 | done | property tests, fuzz targets, benchmarks, the end-to-end sign-in scenario |
| 0.4.0 | done | the `web-net` feature on web-net 0.7 (cookie on identity and denial) |
| 0.5.0 | next | the schema as configuration (same compile as code); a guest output-cache hook (who may be served from cache); role changes that refresh live sessions instead of ending them |
| 0.6.0 | | wire the security bridge to the in-process event bus once it exists; per-source scoring hooks for the connection gate |
| 0.9.x | | polish and freeze |
| 1.0.0 | maintainer's call | after real use end to end and an adversarial review |

## Publishing order

access-gate and auth-gate publish first; until then this crate resolves them through an untracked `.cargo/config.toml` `[patch.crates-io]`, and its CI cannot pass.
