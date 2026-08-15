# Contributing

Pull requests and issues are more than welcome.

## Getting started

```bash
composer install
```

## Running tests

```bash
composer test
# or directly:
vendor/bin/phpunit
```

## Running static analysis

```bash
composer analyse
```

This runs PHPStan and then Psalm. Both must pass.

## Which branch to target

See the [Version Support](README.md#version-support) table in the README for the full policy. In short:

- **`9.x`** — the active branch. Target this for new features, bug fixes, and PHP/PHPUnit compatibility work.
- **`8.x`** — maintenance only. Target this only for security fixes or low-risk maintenance (CI bumps, doc fixes).
- **`7.x` and older** — unsupported. Please upgrade instead of patching these.

## Before opening a pull request

- Run `composer test` and `composer analyse` locally — CI runs both across a wide PHP/PHPUnit matrix, but catching issues locally first saves a round trip.
- Keep the change focused; unrelated formatting/rewrites make a PR harder to review.
- If your change affects behavior (not just tooling/docs), add or update a test.

## Reporting security vulnerabilities

Please do **not** open a public issue or pull request for security vulnerabilities — see [SECURITY.md](SECURITY.md) for how to report privately.

## Questions

See [SUPPORT.md](SUPPORT.md) for where to ask questions or file bug reports.
