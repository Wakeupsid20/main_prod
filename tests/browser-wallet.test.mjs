import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  randomCredential,
  commitmentOf,
  encryptCredential,
  decryptCredential,
  issueInBrowser,
  proveInBrowser,
  walletBackup,
  importWallet,
  FIELD,
} from "../frontend/browser-wallet.mjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const { groth16 } = require("snarkjs");
function memory() {
  const m = new Map();
  return {
    getItem: (k) => m.get(k) ?? null,
    setItem: (k, v) => m.set(k, v),
    removeItem: (k) => m.delete(k),
    m,
  };
}
const password = "test-only browser wallet passphrase";
test("browser commitments match original circomlibjs commitments", () => {
  for (const secret of ["1", "123456789", randomCredential()]) {
    const result = spawnSync(process.execPath, [path.join(root, "zk.cjs")], {
      input: JSON.stringify({ op: "commit", credential: secret }),
      encoding: "utf8",
    });
    assert.equal(result.status, 0);
    assert.equal(commitmentOf(secret), JSON.parse(result.stdout).commitment);
  }
});
test("random credentials stay in the field and have distinct samples", () => {
  const values = Array.from({ length: 30 }, randomCredential);
  assert.equal(new Set(values).size, values.length);
  for (const v of values) assert(BigInt(v) > 0n && BigInt(v) < FIELD);
});
test("authenticated encrypted wallet rejects wrong passwords and edits", async () => {
  const secret = randomCredential(),
    item = await encryptCredential(secret, password);
  assert.equal(await decryptCredential(item, password), secret);
  assert(!JSON.stringify(item).includes(secret));
  await assert.rejects(() => decryptCredential(item, "wrong-password-value"));
  const raw = Uint8Array.from(atob(item.ciphertext), (c) => c.charCodeAt(0));
  raw[0] ^= 1;
  await assert.rejects(() =>
    decryptCredential(
      { ...item, ciphertext: btoa(String.fromCharCode(...raw)) },
      password,
    ),
  );
  await assert.rejects(() =>
    decryptCredential({ ...item, commitment: "1" }, password),
  );
});
test("issuance submits no credential or passphrase and backup imports encrypted data", async () => {
  const storage = memory();
  let submitted;
  const uid = "abc123".repeat(4);
  const user = await issueInBrowser({
    name: "Browser TEST",
    role: "attendee",
    password,
    storage,
    register: async (body) => {
      submitted = body;
      return { id: uid, commitment: body.commitment };
    },
  });
  assert.deepEqual(Object.keys(submitted).sort(), [
    "commitment",
    "name",
    "role",
  ]);
  assert.equal(user.id, uid);
  assert.equal(storage.m.size, 1);
  assert(![...storage.m.values()].join().includes(password));
  const backup = walletBackup(uid, storage),
    other = memory();
  assert.equal(importWallet(backup, other), uid);
  assert.equal(walletBackup(uid, other), backup);
  assert.throws(() => importWallet(backup, other));
  assert.throws(() => importWallet("x".repeat(4097), other));
});
test("browser-format wallet creates a real Groth16 proof accepted by trusted key", async () => {
  const storage = memory(),
    uid = "def456".repeat(4);
  const user = await issueInBrowser({
    name: "Proof TEST",
    role: "attendee",
    password,
    storage,
    register: async (body) => ({ id: uid, commitment: body.commitment }),
  });
  const prover = {
    fullProve: (input, wasm, zkey, logger, wtns, options) =>
      groth16.fullProve(
        input,
        path.join(root, "build/session/auth_session_js/auth_session.wasm"),
        path.join(root, "build/session/final.zkey"),
        logger,
        wtns,
        options,
      ),
  };
  const challenge = {
    id: "test-challenge",
    commitment: user.commitment,
    challenge: "987654321",
  };
  const result = await proveInBrowser({
    uid,
    password,
    challenge,
    storage,
    prover,
  });
  assert.deepEqual(result.publicSignals.slice(1), [
    user.commitment,
    challenge.challenge,
  ]);
  const key = JSON.parse(
    await readFile(path.join(root, "build/session/verification_key.json")),
  );
  assert(await groth16.verify(key, result.publicSignals, result.proof));
  const cloudVerification = spawnSync(
    process.execPath,
    [path.join(root, "zk.cjs")],
    {
      env: { ...process.env, ZKP_CLOUD: "1" },
      input: JSON.stringify({
        op: "verify",
        proof: result.proof,
        publicSignals: result.publicSignals,
      }),
      encoding: "utf8",
      timeout: 30000,
    },
  );
  assert.equal(cloudVerification.status, 0, cloudVerification.stderr);
  assert.equal(JSON.parse(cloudVerification.stdout).valid, true);
  assert(
    !(await groth16.verify(
      key,
      [result.publicSignals[0], user.commitment, "123"],
      result.proof,
    )),
  );
});
// snarkjs verification may retain curve workers. Keep an explicit isolated test exit.
test.after(() => {
  setTimeout(() => process.exit(process.exitCode || 0), 100).unref();
});
