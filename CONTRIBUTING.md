# Contributing

pr-sentinel is dual-licensed under MIT OR Apache-2.0. By contributing, you
agree that your contributions are available under those same licenses.

## Development

Stable Rust, as pinned by `rust-toolchain.toml`. From the repository root:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

`cargo fmt --all` is required because this is a virtual workspace; `cargo fmt`
with no package selected does not see the crates.

The DB-IP databases are not in git. The reader test skips when they are
absent, and runs when they are present:

```bash
cargo xtask download-geodb
cargo test -p ps-enrich
```

Do not commit `data/*.mmdb` or generated JSONL. The download is CC BY 4.0;
the attribution line belongs in the README, which already has it.

## Tests

Detectors are tested directly, with property tests where the statement is
universal (score monotonicity, haversine symmetry, "the same coordinates are
not travel"). The seeded dataset test in `ps-cli` is the end-to-end check:
injected attacks cross the alert line, and ordinary logins do not.

Do not paste benchmark timings into comments, docs, or tests. Criterion is
wired as a stub for a later milestone; `cargo bench -p ps-engine` runs it,
and CI does not.

## Pull requests

- Keep the change scoped to one concern.
- Explain the scoring or state consequence when a detector changes. A weight
  change needs a reason, not just a new number.
- Synthetic data only. No production logs, no customer identifiers, no
  redistributed MaxMind or DB-IP database files.
