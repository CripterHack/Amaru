# Contributing to Amaru

Amaru targets Windows 11 x64. The project overview describes the intended product. Check the latest validation record before relying on a component or documenting it as available. [Project overview](README.md) · [Development status](status_development.md)

## From specification to change

Start with the relevant issue or guide. Describe the user-visible behavior, supported inputs, expected result and failure behavior. Identify how to reproduce each acceptance check. For detection changes, include a benign control and the expected rule identifier. The EICAR specification gives a worked example with a pinned upstream corpus. [Detection acceptance criteria](docs/technical/eicar-corpus.md)

Keep the implementation, regression check and affected documentation together. In the pull request, record the commands, platform, results and anything that still needs testing on Windows.

## Running focused checks

Run these commands from the repository root in a Python 3.12 virtual environment to validate the signatures and the optional YARA-X scanner.

```sh
python -m pip install --only-binary=:all: -r scripts/requirements-signatures.txt
python -m unittest discover -s tests -p 'test_*.py' -v
```

Run the Rust engine tests with Cargo, a C compiler, libclang and OpenSSL development files. On Ubuntu the latter two packages are `libclang-dev` and `libssl-dev`.

```sh
cargo test --locked -p yara-engine
```

The frontend uses Node.js 22 in CI. Its component tests exercise Tauri calls with test doubles.

```sh
cd gui
npm ci
npm test
npm run build
```

CI also checks Markdown links to tracked documents and their headings with lychee in offline mode. Changes to the desktop service or installer need an additional Windows installation and runtime check. Record the exact build that was used. [Validation workflow](.github/workflows/validation.yml) · [Installer build](installer/README.md)
