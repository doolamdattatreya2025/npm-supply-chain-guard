#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const RISKY_SCRIPTS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "preuninstall",
  "postuninstall",
]);

const SUSPICIOUS_PATTERNS = [
  { regex: /\bcurl\b/i, reason: "downloads external content with curl" },
  { regex: /\bwget\b/i, reason: "downloads external content with wget" },
  { regex: /\bfetch\b/i, reason: "fetch usage may download remote payloads" },
  { regex: /\bInvoke-WebRequest\b/i, reason: "PowerShell remote download command" },
  { regex: /\bbase64\b/i, reason: "possible obfuscation using base64" },
  { regex: /\bchmod\s+\+x\b/i, reason: "changes file permissions to executable" },
  { regex: /\beval\b/i, reason: "dynamic code execution with eval" },
  { regex: /\bchild_process\b/i, reason: "spawns system commands via child_process" },
  { regex: /\bpowershell\b/i, reason: "executes PowerShell commands" },
  { regex: /\bbash\b/i, reason: "executes bash commands" },
  { regex: /\bsh\b/i, reason: "executes shell commands" },
  { regex: /https?:\/\//i, reason: "contains remote URL" },
];

function safeReadJson(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    return { ok: true, data: JSON.parse(raw) };
  } catch (error) {
    return { ok: false, error };
  }
}

function collectWarnings() {
  return [];
}

function addWarning(warnings, type, message, meta = {}) {
  warnings.push({ type, message, ...meta });
}

function scanScripts(pkg, warnings) {
  if (!pkg.scripts || typeof pkg.scripts !== "object") return;

  for (const [scriptName, scriptValue] of Object.entries(pkg.scripts)) {
    if (RISKY_SCRIPTS.has(scriptName)) {
      addWarning(
        warnings,
        "risky-script",
        `Risky lifecycle script: ${scriptName} -> ${scriptValue}`,
        { scriptName, scriptValue }
      );
    }

    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.regex.test(String(scriptValue))) {
        addWarning(
          warnings,
          "suspicious-command",
          `Suspicious command in script "${scriptName}": ${pattern.reason}`,
          { scriptName, scriptValue, reason: pattern.reason }
        );
      }
    }
  }
}

function isWideVersionRange(version) {
  return /^[~^><=]/.test(version);
}

function scanDependencies(pkg, warnings) {
  const deps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.optionalDependencies || {}),
  };

  for (const [name, version] of Object.entries(deps)) {
    const normalized = String(version);

    if (/^(git\+|github:|https?:\/\/|file:)/i.test(normalized)) {
      addWarning(
        warnings,
        "suspicious-source",
        `Suspicious dependency source: ${name}@${normalized}`,
        { dependency: name, version: normalized }
      );
    }

    if (normalized === "latest" || normalized === "*") {
      addWarning(
        warnings,
        "unsafe-version",
        `Unsafe version tag: ${name}@${normalized}`,
        { dependency: name, version: normalized }
      );
    }

    if (isWideVersionRange(normalized)) {
      addWarning(
        warnings,
        "wide-version-range",
        `Wide version range detected: ${name}@${normalized}`,
        { dependency: name, version: normalized }
      );
    }
  }
}

function scanPackageLock(projectPath, warnings) {
  const lockPath = path.join(projectPath, "package-lock.json");

  if (!fs.existsSync(lockPath)) return;

  const result = safeReadJson(lockPath);
  if (!result.ok) {
    addWarning(
      warnings,
      "invalid-lockfile",
      `Could not parse package-lock.json: ${result.error.message}`
    );
    return;
  }

  const lock = result.data;

  if (lock.packages && typeof lock.packages === "object") {
    for (const [pkgPath, meta] of Object.entries(lock.packages)) {
      if (!meta || typeof meta !== "object") continue;

      if (meta.resolved && /^https?:\/\//i.test(meta.resolved)) {
        addWarning(
          warnings,
          "remote-resolved-package",
          `Lockfile package resolved from remote URL: ${pkgPath || "."} -> ${meta.resolved}`,
          { packagePath: pkgPath, resolved: meta.resolved }
        );
      }

      if (meta.hasInstallScript === true) {
        addWarning(
          warnings,
          "install-script-in-lockfile",
          `Dependency has install script: ${pkgPath || "."}`,
          { packagePath: pkgPath }
        );
      }
    }
  }
}

function formatWarning(index, warning) {
  return `⚠ [${index}] ${warning.message}`;
}

function scanProject(projectPath = ".") {
  const resolvedProjectPath = path.resolve(projectPath);
  const pkgPath = path.join(resolvedProjectPath, "package.json");
  const warnings = collectWarnings();

  if (!fs.existsSync(pkgPath)) {
    console.error("❌ package.json not found");
    return { ok: false, warnings, error: "package.json not found" };
  }

  const pkgResult = safeReadJson(pkgPath);
  if (!pkgResult.ok) {
    console.error(`❌ Failed to parse package.json: ${pkgResult.error.message}`);
    return { ok: false, warnings, error: pkgResult.error.message };
  }

  const pkg = pkgResult.data;

  console.log(`🔍 Scanning project: ${resolvedProjectPath}\n`);

  scanScripts(pkg, warnings);
  scanDependencies(pkg, warnings);
  scanPackageLock(resolvedProjectPath, warnings);

  if (warnings.length === 0) {
    console.log("✅ No obvious supply-chain risks found");
  } else {
    warnings.forEach((warning, index) => {
      console.log(formatWarning(index + 1, warning));
    });
    console.log(`\n⚠ Total warnings: ${warnings.length}`);
  }

  console.log("\n✅ Scan complete");

  return { ok: true, warnings };
}

if (require.main === module) {
  const target = process.argv[2] || ".";
  const result = scanProject(target);

  if (!result.ok) {
    process.exit(1);
  }

  if (result.warnings.length > 0) {
    process.exitCode = 1;
  }
}

module.exports = {
  scanProject,
  safeReadJson,
  scanScripts,
  scanDependencies,
  scanPackageLock,
};