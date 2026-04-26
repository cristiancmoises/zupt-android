# Contributing to Zupt

Thanks for your interest in improving Zupt. Privacy and cryptographic correctness matter here, so contributions go through some review.

## License agreement

By contributing, you agree your contributions are licensed under AGPL-3.0-or-later, the same as the rest of the project. Add a `Signed-off-by:` line to your commits per the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "your message"
```

## Code style

- **Kotlin idiomatic.** Prefer `val`, immutable data, expression-bodied functions where they fit.
- **No trailing whitespace.** No tabs. 4-space indentation. Configure your editor.
- **Lines under 120 columns.** Soft-wrap long strings.
- **Imports** explicit, no wildcards.
- **Names**: `PascalCase` for types, `camelCase` for vals/funs, `UPPER_SNAKE` for `const val`.

## Testing requirements

Cryptographic and archive-format changes MUST come with a test:

- **JVM tests** in `app/src/test/java/co/securityops/zupt/test/` — these are the unit tests that compile-and-run via `kotlinc` directly without Gradle/Android. They run fast and cover the security-critical paths.
- For UI changes, manual testing on at least Android 8 (minSdk) and Android 14 (targetSdk).

Cryptographic changes require:
1. Round-trip test demonstrating the change preserves correctness
2. Reasoning about the threat model and what changed
3. Reference to the relevant standard (NIST publication, RFC, peer-reviewed paper)

## Pull request workflow

1. Fork → branch off `main`
2. Make changes, add tests, run `./gradlew :app:assembleRelease` locally
3. Update `CHANGELOG.md` under an `## [Unreleased]` section if your change ships in the next release
4. Push, open PR
5. CI must pass (build + lint)
6. Maintainer review, possibly with requested changes
7. Squash-merge with a clean commit message

Avoid PRs that mix unrelated changes. Each PR should have a single coherent purpose.

## What's in scope

Welcome:
- Bug fixes (especially security/correctness)
- Performance improvements with benchmarks
- New compression codecs (Zstd is high on the list)
- UI/UX improvements that respect the existing aesthetic
- Documentation, especially for the wire format and threat model
- Translations (i18n) — string resources in `app/src/main/res/values-*/`

Less welcome:
- Telemetry, analytics, "anonymous" metrics — Zupt sends nothing, ever
- Cloud sync features — out of scope by design
- Ads, in-app purchases, premium tiers — Zupt is free software
- Adding INTERNET permission — non-negotiable

## Cryptographic changes

Changes touching `co.securityops.zupt.core.crypto` or `co.securityops.zupt.core.archive` need extra scrutiny:

- Discuss the change in an issue *before* coding it
- Cite peer-reviewed sources for any new primitive or construction
- Provide test vectors when possible (especially for KDFs and AEADs)
- Document the wire format change in `SPEC.md` if the archive layout changes
- Bump the format version (`Format.VERSION_MINOR` or `_MAJOR`) per semver conventions

## Maintainer

**Cristian Cezar Moisés** — cristian@securityops.co

For matters not covered here, ping the maintainer or open a discussion issue.
