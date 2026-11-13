const { spawnSync } = require("child_process");
const path = require("path");
const root = path.resolve(__dirname, "..");
let result = spawnSync(
  process.execPath,
  [path.join(__dirname, "prepare-cloud-assets.cjs")],
  { cwd: root, stdio: "inherit" },
);
if (result.status !== 0) process.exit(result.status || 1);
result = spawnSync(
  process.execPath,
  [path.join(root, "node_modules/vite/bin/vite.js"), "build"],
  {
    cwd: root,
    env: { ...process.env, VITE_WALLET_MODE: "browser" },
    stdio: "inherit",
  },
);
process.exit(result.status || 0);
