# UniGroth — Scripts

Utility scripts for development tooling.

## `install-hook.sh`

Installs the pre-commit hook from `.hooks/pre-commit` into `.git/hooks/`.

```bash
./scripts/install-hook.sh
```

The hook runs `cargo fmt --check` and `cargo clippy -- -D warnings` before every commit.

## `linkify_changelog.py`

Post-processes `CHANGELOG.md` to convert issue/PR references into GitHub links.

```bash
python3 scripts/linkify_changelog.py
```

Converts patterns like `#123` into `[#123](https://github.com/MeridianAlgo/UniGroth/issues/123)`.
