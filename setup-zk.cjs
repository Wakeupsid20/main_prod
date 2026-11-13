// LOCAL DEMO CEREMONY ONLY: all contributions run on one machine.
const fs = require("fs"),
  path = require("path"),
  { spawnSync } = require("child_process"),
  crypto = require("crypto");
const target = path.join(__dirname, "build/session");
const out = path.join(__dirname, "build", "session-" + Date.now());
fs.mkdirSync(out, { recursive: true });
function run(script, args) {
  const r = spawnSync(
    process.execPath,
    [path.join(__dirname, "node_modules", script), ...args],
    { cwd: __dirname, stdio: "inherit" },
  );
  if (r.status !== 0) process.exit(r.status || 1);
}
function sn(...args) {
  run("snarkjs/cli.js", args);
}
run("circom2/cli.js", [
  "auth_session.circom",
  "--r1cs",
  "--wasm",
  "--sym",
  "-o",
  out,
]);
sn("powersoftau", "new", "bn128", "11", path.join(out, "p0.ptau"));
sn(
  "powersoftau",
  "contribute",
  path.join(out, "p0.ptau"),
  path.join(out, "p1.ptau"),
  "--name=Local demo",
  "-e=" + crypto.randomBytes(64).toString("hex"),
);
sn(
  "powersoftau",
  "prepare",
  "phase2",
  path.join(out, "p1.ptau"),
  path.join(out, "powers.ptau"),
);
sn(
  "groth16",
  "setup",
  path.join(out, "auth_session.r1cs"),
  path.join(out, "powers.ptau"),
  path.join(out, "initial.zkey"),
);
sn(
  "zkey",
  "contribute",
  path.join(out, "initial.zkey"),
  path.join(out, "final.zkey"),
  "--name=Local demo phase2",
  "-e=" + crypto.randomBytes(64).toString("hex"),
);
sn(
  "zkey",
  "verify",
  path.join(out, "auth_session.r1cs"),
  path.join(out, "powers.ptau"),
  path.join(out, "final.zkey"),
);
sn(
  "zkey",
  "export",
  "verificationkey",
  path.join(out, "final.zkey"),
  path.join(out, "verification_key.json"),
);
const artifacts = [
  "auth_session_js/auth_session.wasm",
  "final.zkey",
  "verification_key.json",
];
const manifest = {
  circuit: crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(__dirname, "auth_session.circom")))
    .digest("hex"),
  files: {},
};
for (const f of artifacts)
  manifest.files[f] = crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(out, f)))
    .digest("hex");
fs.writeFileSync(
  path.join(out, "manifest.json"),
  JSON.stringify(manifest, null, 2),
);
if (fs.existsSync(target))
  fs.renameSync(target, target + "-backup-" + Date.now());
fs.renameSync(out, target);
console.log(
  "Demo setup complete. Production requires an independent audited ceremony.",
);
