#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

// --- CONFIGURATION & THREAT MODELS ---

const RISKY_SCRIPTS = new Set(["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]);

const TOP_PACKAGES = ["lodash", "express", "react", "vue", "axios", "chalk", "moment", "dotenv"];

const SUSPICIOUS_PATTERNS = [
  { regex: /\bcurl\b/i, reason: "downloads external content with curl", severity: "high" },
  { regex: /\bwget\b/i, reason: "downloads external content with wget", severity: "high" },
  { regex: /\beval\b/i, reason: "dynamic code execution with eval", severity: "high" },
  { regex: /\bbase64\b/i, reason: "possible obfuscation using base64", severity: "medium" },
  { regex: /https?:\/\//i, reason: "contains remote URL", severity: "medium" },
];

const CLOUD_RISKS = [
  { regex: /169\.254\.169\.254/, reason: "Attempts to access Cloud Instance Metadata (AWS/GCP/Azure) - critical credential theft risk", severity: "high" },
  { regex: /metadata\.google\.internal/i, reason: "Attempts to access GCP metadata endpoint", severity: "high" },
  { regex: /AKIA[0-9A-Z]{16}/, reason: "Hardcoded AWS Access Key ID detected", severity: "high" },
  { regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/, reason: "Hardcoded Slack Token detected", severity: "high" }
];

// --- UTILITIES ---

function getEditDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      
        matrix[i][j - 1] + 1,      
        matrix[i - 1][j - 1] + cost 
      );
    }
  }
  return matrix[a.length][b.length];
}

function addWarning(warnings, type, message, severity = "low", meta = {}) {
  warnings.push({ type, message, severity, ...meta });
}

// --- SCANNING ENGINES ---

function scanCloudRisks(pkg, warnings) {
  // We stringify the package to catch secrets hidden anywhere (descriptions, custom fields, scripts)
  const pkgString = JSON.stringify(pkg);
  
  for (const risk of CLOUD_RISKS) {
    if (risk.regex.test(pkgString)) {
      addWarning(warnings, "cloud-risk", `Cloud security threat: ${risk.reason}`, risk.severity);
    }
  }
}

function scanTyposquatting(name, warnings) {
  for (const topPkg of TOP_PACKAGES) {
    if (name === topPkg) continue;
    const distance = getEditDistance(name, topPkg);
    if (distance === 1) {
      addWarning(warnings, "typosquatting", `Possible typosquatting detected: "${name}" is very similar to "${topPkg}"`, "high", { target: topPkg });
    }
  }
}

function scanScripts(pkg, warnings) {
  if (!pkg.scripts) return;
  for (const [name, val] of Object.entries(pkg.scripts)) {
    if (RISKY_SCRIPTS.has(name)) {
      addWarning(warnings, "risky-script", `Risky lifecycle script: ${name}`, "medium");
    }
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.regex.test(String(val))) {
        addWarning(warnings, "suspicious-command", `Suspicious command in "${name}": ${pattern.reason}`, pattern.severity);
      }
    }
  }
}

function scanPackageLock(projectPath, warnings) {
  const lockPath = path.join(projectPath, "package-lock.json");
  if (!fs.existsSync(lockPath)) return;

  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
    const packages = lock.packages || {};

    for (const [pkgPath, meta] of Object.entries(packages)) {
      if (!pkgPath) continue;
      const name = pkgPath.split("node_modules/").pop();

      if (name) scanTyposquatting(name, warnings);

      if (meta.hasInstallScript) {
        addWarning(warnings, "hidden-install-script", `Nested dependency has install script: ${pkgPath}`, "medium");
      }
    }
  } catch (e) {
    addWarning(warnings, "error", "Failed to parse lockfile");
  }
}

// --- OUTPUT FORMATTERS ---

function printSarif(warnings) {
  const sarif = {
    version: "2.1.0",
    $schema: "http://json.schemastore.org/sarif-2.1.0-rtm.5",
    runs: [
      {
        tool: {
          driver: {
            name: "npm-supply-chain-guard",
            informationUri: "https://github.com/doolamdattatreya2025/npm-supply-chain-guard",
            rules: []
          }
        },
        results: warnings.map(w => ({
          ruleId: w.type,
          level: w.severity === "high" ? "error" : "warning",
          message: { text: w.message }
        }))
      }
    ]
  };
  console.log(JSON.stringify(sarif, null, 2));
}

// --- MAIN RUNNER ---

function scanProject(projectPath = ".", outputFormat = "text") {
  const resolvedPath = path.resolve(projectPath);
  const pkgPath = path.join(resolvedPath, "package.json");
  const warnings = [];

  if (!fs.existsSync(pkgPath)) return { ok: false, error: "No package.json found" };

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));

  // Run all engines
  scanScripts(pkg, warnings);
  scanCloudRisks(pkg, warnings);
  scanPackageLock(resolvedPath, warnings);

  if (outputFormat === "sarif") {
    printSarif(warnings);
    return { ok: true, warnings };
  }

  // Print Standard Results
  console.log(`\x1b[34m🔍 Scanning: ${resolvedPath}\x1b[0m\n`);
  
  if (warnings.length === 0) {
    console.log("\x1b[32m✅ No risks detected.\x1b[0m");
  } else {
    warnings.forEach((w, i) => {
      const color = w.severity === "high" ? "\x1b[31m" : "\x1b[33m";
      console.log(`${color}⚠ [${i + 1}] [${w.severity.toUpperCase()}] ${w.message}\x1b[0m`);
    });
    console.log(`\nTotal Warnings: ${warnings.length}`);
  }

  return { ok: true, warnings };
}

// CLI Entrypoint
if (require.main === module) {
  const args = process.argv.slice(2);
  const isSarif = args.includes("--sarif");
  const targetDir = args.find(arg => !arg.startsWith("--")) || ".";

  const result = scanProject(targetDir, isSarif ? "sarif" : "text");
  
  const hasHighRisk = result.warnings?.some(w => w.severity === "high");
  process.exit(hasHighRisk ? 1 : 0);
}

module.exports = { scanProject };