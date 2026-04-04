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

// --- UTILITIES ---

// Fast O(n) check for a single character insertion, deletion, or substitution
function isOneIndexChange(target, input) {
  if (target === input || Math.abs(target.length - input.length) > 1) return false;
  
  let i = 0, j = 0, diffs = 0;
  while (i < target.length && j < input.length) {
    if (target[i] !== input[j]) {
      diffs++;
      if (diffs > 1) return false;
      if (target.length > input.length) j--; // target has extra char
      else if (input.length > target.length) i--; // input has extra char
    }
    i++;
    j++;
  }
  return true;
}

function addWarning(warnings, type, message, severity = "low", meta = {}) {
  warnings.push({ type, message, severity, ...meta });
}

// --- SCANNING ENGINES ---

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

function scanDependencies(pkg, warnings) {
  const deps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.optionalDependencies || {}),
  };

  for (const [name, version] of Object.entries(deps)) {
    const normalized = String(version);

    // 1. Check for suspicious sources (git, http)
    if (/^(git\+|github:|https?:\/\/|file:)/i.test(normalized)) {
      addWarning(warnings, "suspicious-source", `Suspicious dependency source: ${name}@${normalized}`, "high");
    }

    // 2. Check for unsafe versioning (latest, *)
    if (normalized === "latest" || normalized === "*") {
      addWarning(warnings, "unsafe-version", `Unsafe version tag: ${name}@${normalized}`, "medium");
    }

    // 3. Check for wide ranges
    if (/^[~^><=]/.test(normalized)) {
      addWarning(warnings, "wide-version-range", `Wide version range detected: ${name}@${normalized}`, "low");
    }

    // 4. Fast Typosquatting Check
    for (const topPkg of TOP_PACKAGES) {
      if (isOneIndexChange(topPkg, name)) {
        addWarning(
          warnings, 
          "typosquatting", 
          `High Risk: "${name}" looks like a typosquatting attempt of "${topPkg}"`, 
          "high", 
          { dependency: name, target: topPkg }
        );
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

      // Typosquatting check for every nested dependency in the tree
      if (name) {
        for (const topPkg of TOP_PACKAGES) {
          if (isOneIndexChange(topPkg, name)) {
             addWarning(warnings, "typosquatting", `Nested Typosquatting detected: "${name}" mimics "${topPkg}"`, "high");
          }
        }
      }

      // Deep Install Script Check
      if (meta.hasInstallScript) {
        addWarning(warnings, "hidden-install-script", `Nested dependency has install script: ${pkgPath}`, "medium");
      }
    }
  } catch (e) {
    addWarning(warnings, "error", "Failed to parse lockfile", "low");
  }
}

// --- MAIN RUNNER ---

function scanProject(projectPath = ".") {
  const resolvedPath = path.resolve(projectPath);
  const pkgPath = path.join(resolvedPath, "package.json");
  const warnings = [];

  if (!fs.existsSync(pkgPath)) {
    console.error(`\x1b[31m❌ Error: No package.json found at ${resolvedPath}\x1b[0m`);
    return { ok: false, error: "No package.json found" };
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  } catch (e) {
    console.error(`\x1b[31m❌ Error: Failed to parse package.json\x1b[0m`);
    return { ok: false, error: "Failed to parse package.json" };
  }

  console.log(`\x1b[34m🔍 Scanning: ${resolvedPath}\x1b[0m\n`);

  // --- THE FIX: ALL ENGINES NOW RUN ---
  scanScripts(pkg, warnings);
  scanDependencies(pkg, warnings); 
  scanPackageLock(resolvedPath, warnings);

  // Print Results with Colors
  if (warnings.length === 0) {
    console.log("\x1b[32m✅ No risks detected.\x1b[0m");
  } else {
    warnings.forEach((w, i) => {
      let color = "\x1b[37m"; // White default
      if (w.severity === "high") color = "\x1b[31m"; // Red
      if (w.severity === "medium") color = "\x1b[33m"; // Yellow
      if (w.severity === "low") color = "\x1b[36m"; // Cyan
      
      console.log(`${color}⚠ [${i + 1}] [${w.severity.toUpperCase()}] ${w.message}\x1b[0m`);
    });
    console.log(`\nTotal Warnings: ${warnings.length}`);
  }

  return { ok: true, warnings };
}

// CLI Entrypoint
if (require.main === module) {
  const result = scanProject(process.argv[2] || ".");
  
  // Exit with error code 1 only if HIGH severity risks are found
  const hasHighRisk = result.warnings?.some(w => w.severity === "high");
  process.exit(hasHighRisk ? 1 : 0);
}

module.exports = { scanProject };