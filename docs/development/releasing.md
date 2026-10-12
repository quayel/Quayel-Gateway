# Making a release

Releases are built automatically by [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

1. As you make changes, add a line for each user-visible one under `## [Unreleased]` in [`CHANGELOG.md`](../../CHANGELOG.md), in **Breaking changes**, **Added**, **Changed** or **Fixed**.
2. When releasing, rename `## [Unreleased]` to `## [0.3.0] - YYYY-MM-DD`, add a new empty `## [Unreleased]` above it, and set `version` in `Cargo.toml` to match. Preview the notes with `scripts/release-notes.sh v0.3.0`.
3. Run every test suite with `bash scripts/test/run-all.sh`.
4. Commit, then push a matching tag:

```bash
git tag -a v0.3.0 -m "v0.3.0"
git push origin main v0.3.0
```

GitHub Actions then:

- tests and builds the x86_64 and ARM64 binaries with fresh IP data
- packages them as `.tar.gz` and `.deb` files, plus `SHA256SUMS`
- creates the GitHub release, using that version's `CHANGELOG.md` section plus install instructions as the notes
- pushes the Docker image to `ghcr.io/quayel/quayel-gateway` and Docker Hub (`quayel/quayel-gateway`), tagged `:latest`, `:<version>` and `:<major>.<minor>`

The Docker Hub push needs the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repo secrets; without them it's skipped.

The build stops if the tag doesn't match `Cargo.toml` or `CHANGELOG.md` has no section for that version. A tag with a suffix, such as `v0.3.0-rc.1`, is published as a pre-release and doesn't move the `latest` image tag.

## Refreshing the IP data

The release build downloads fresh IP databases, so every release ships current data. To refresh a self-built Docker image, rebuild it: if `src/data/` is empty, the build downloads the data. Do it about once a month to get the latest DB-IP data.
