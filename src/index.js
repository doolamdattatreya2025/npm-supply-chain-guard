const fs = require("fs");
const path = require("path");

function scanProject(projectPath) {
  const pkgPath = path.join(projectPath, "package.json");

  if (!fs.existsSync(pkgPath)) {
    console.log("❌ package.json not found");
    return;
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));

  console.log("🔍 Scanning project...\n");

  // Check scripts
  if (pkg.scripts) {
    Object.entries(pkg.scripts).forEach(([key, value]) => {
      if (["postinstall", "preinstall"].includes(key)) {
        console.log(`⚠ Risky Script: ${key} -> ${value}`);
      }
    });
  }

  // Check dependencies
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  Object.entries(deps || {}).forEach(([name, version]) => {
    if (version.includes("git") || version.includes("http")) {
      console.log(`⚠ Suspicious dependency source: ${name}`);
    }

    if (version === "latest" || version === "*") {
      console.log(`⚠ Unsafe version: ${name}@${version}`);
    }
  });

  console.log("\n✅ Scan complete");
}

const target = process.argv[2] || ".";
scanProject(target);