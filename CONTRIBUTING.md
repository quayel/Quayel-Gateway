# Contributing to Quayel Gateway

Thanks for helping. Bug reports, documentation fixes, test cases and pull
requests are all welcome.

- **Questions and help:** [open an issue](https://github.com/quayel/Quayel-Gateway/issues/new/choose) with the *Question* template.
- **Bugs:** use the *Bug report* template. Include `quayel-gateway --version`, the relevant part of your `config.json` (remove secrets) and the gateway's log output.
- **Security issues:** don't open a public issue. See [SECURITY.md](SECURITY.md).
- **Documentation:** the user docs are published at [docs.quayel.com](https://docs.quayel.com). The Markdown in [`docs/`](docs/) is the source of truth for behaviour; if you find a mistake on the site, open an issue here.

## Before you start on a bigger change

Open an issue first and describe what you want to change and why. Quayel
keeps the whole product in one binary and one config file, and some features
(an Admin API, scripting, a shared cache) change that design, so it's worth
agreeing on the approach before you write the code.

## Development setup

You need Linux (x86_64 or aarch64). On macOS, use a Linux VM or container.

```bash
git clone https://github.com/quayel/Quayel-Gateway.git
cd Quayel-Gateway
./setup.sh                 # Rust toolchain, build tools and the IP datasets (into src/data/)
cargo build --release      # the datasets are compiled into the binary
./target/release/quayel-gateway examples/config.quickstart.json
```

`./setup.sh --data-only` refreshes only the datasets; `--cargo-only` skips them.
A release build takes a few minutes because about 140 MB of IP data is embedded.

## Tests

```bash
cargo test --release                 # unit tests
bash scripts/test/run-all.sh         # every suite: unit tests plus the live suites
```

The live suites start the gateway against real services (ClickHouse, Loki,
Pebble for ACME, gRPC servers, Redis, PostgreSQL) and print one `PASS` /
`FAIL` line per check. Suites that need Docker are skipped when it isn't
available. See [Testing](https://docs.quayel.com/quayel-gateway/contributing/testing)
for what each suite covers.

Add a test with every behaviour change: a unit test next to the code, and a
check in the matching suite under `scripts/test/` when the behaviour is only
visible end to end.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. Unrelated fixes go in their own pull request.
3. Run `cargo test --release` and the suites your change touches.
4. Format new or changed files with `rustfmt`.
5. Update the docs in `docs/` and `docs/config.schema.json` when you add or
   change a config field, and add an entry under `## [Unreleased]` in
   [CHANGELOG.md](CHANGELOG.md), written for people running the gateway.
6. Performance changes need numbers: follow the
   [benchmark protocol](docs/development/benchmark-protocol.md) and include
   the before/after table in the pull request.

By opening a pull request you agree that your contribution is licensed under
the [Apache License 2.0](LICENSE), the same as the project.

Be kind and assume good intent in issues and reviews.
