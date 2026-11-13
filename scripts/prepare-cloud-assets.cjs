const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const root = path.resolve(__dirname, ".."),
  source = path.join(root, "build/session");
const manifest = JSON.parse(
  fs.readFileSync(path.join(source, "manifest.json")),
);
for (const [file, expected] of Object.entries(manifest.files)) {
  const hash = crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(source, file)))
    .digest("hex");
  if (hash !== expected) throw Error("Artifact manifest mismatch: " + file);
}
const target = path.join(root, "public/zk");
fs.mkdirSync(target, { recursive: true });
fs.copyFileSync(
  path.join(source, "auth_session_js/auth_session.wasm"),
  path.join(target, "auth_session.wasm"),
);
fs.copyFileSync(
  path.join(source, "final.zkey"),
  path.join(target, "final.zkey"),
);
console.log(
  "Public demo proving artifacts prepared. No holder credentials copied.",
);
