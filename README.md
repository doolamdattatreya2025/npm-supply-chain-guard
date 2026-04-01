# 🔐 npm-supply-chain-guard

A lightweight Node.js CLI tool to detect **npm supply-chain security risks** in JavaScript projects.

---

## 🚨 Why this project?

Real-world incidents like the compromise of popular npm packages have shown that even trusted dependencies can be weaponized.

This project is inspired by such supply-chain attacks, where malicious code is injected into widely used libraries.

The goal is to help developers identify risky patterns early — before they become serious security issues.

---

## ⚙️ Features

* 🔍 Detects risky lifecycle scripts (`postinstall`, `preinstall`)
* 🧪 Flags suspicious or potentially malicious shell commands
* 📦 Identifies non-registry dependencies (Git URLs, remote sources)
* ⚠️ Warns about unsafe versioning (`latest`, `*`)
* 🔐 Analyzes `package-lock.json` inconsistencies
* 🛠 Fast and lightweight CLI-based scanning

---

## 📦 Installation

```bash
git clone https://github.com/doolamdattatreya2025/npm-supply-chain-guard.git
cd npm-supply-chain-guard
npm install
```

---

## ▶️ Usage

Scan the current project:

```bash
node src/index.js .
```

Scan a different project:

```bash
node src/index.js /path/to/project
```

---

## 🧪 Run Tests

```bash
npm test
```

---

## 🛡 Example Output

```bash
⚠ Risky Script Detected: postinstall -> node install.js
⚠ Suspicious Dependency Source: lodash (Git URL)
⚠ Unsafe Version Tag: express@latest
```

---

## 🧠 What It Detects

* Supply-chain attack patterns
* Malicious install-time execution
* Dependency trust issues
* Risky or unverified package sources

---

## 📸 Demo

![CLI Demo](./assets/demo.png)

---

## 🚀 Future Improvements

* SARIF report export (for CI/CD integration)
* GitHub Security integration
* Typosquatting detection
* Advanced static analysis of dependencies
* Web-based dashboard for visualization

---

## 📜 License

MIT License

---

## 👨‍💻 Author

**DATTATREYA**
Cybersecurity Student
GitHub: https://github.com/doolamdattatreya2025
