# 🔐 npm-supply-chain-guard

A lightweight Node.js CLI tool to detect **npm supply-chain attack risks** in your projects.

---

## 🚨 Why this project?

Modern attacks like the compromise of Axios show that even trusted dependencies can be weaponized.

This tool helps developers identify risky patterns before they become security incidents.

---

## ⚙️ Features

* 🔍 Detects risky lifecycle scripts (`postinstall`, `preinstall`)
* 🧪 Flags obfuscated or suspicious shell commands
* 📦 Identifies non-registry dependencies (Git URLs, remote sources)
* ⚠️ Warns about unsafe versioning (`latest`, `*`)
* 🔐 Analyzes `package-lock.json` inconsistencies
* 🛠 CLI-based fast scanning

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/npm-supply-chain-guard.git
cd npm-supply-chain-guard
npm install
```

---

## ▶️ Usage

```bash
node ./src/index.js ./your-project
```

---

## 🧪 Run Tests

```bash
npm test
```

---

## 🛡 Example Output

```bash
⚠ Risky Script Detected: postinstall
⚠ Suspicious Dependency Source: Git URL
⚠ Unsafe Version Tag: latest
```

---

## 🧠 What It Detects

* Supply chain attack patterns
* Malicious install-time execution
* Dependency trust issues

---

## 🚀 Future Improvements

* SARIF report export
* GitHub Security integration
* Typosquatting detection
* Web dashboard

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Ram (Cybersecurity Student)
