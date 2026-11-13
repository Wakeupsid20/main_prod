const fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const dir = path.join(__dirname, "build/session");
async function main() {
  const data = JSON.parse(fs.readFileSync(0, "utf8"));
  if (data.op === "commit") {
    const poseidon = await buildPoseidon();
    return {
      commitment: poseidon.F.toString(poseidon([BigInt(data.credential)])),
    };
  }
  if (data.op === "prove")
    return await snarkjs.groth16.fullProve(
      data.input,
      path.join(dir, "auth_session_js/auth_session.wasm"),
      path.join(dir, "final.zkey"),
    );
  if (data.op === "verify") {
    if (process.env.ZKP_CLOUD === "1") {
      // snarkjs 0.7.6 reuses ffjavascript's BN128 cache. Prewarm that cache
      // with its official single-thread engine to avoid host-CPU-sized pools
      // on a small cloud instance. Proof equations and trusted key stay intact.
      const ff = require("ffjavascript");
      globalThis.curve_bn128 = await ff.buildBn128(true);
    }
    return {
      valid: await snarkjs.groth16.verify(
        JSON.parse(fs.readFileSync(path.join(dir, "verification_key.json"))),
        data.publicSignals,
        data.proof,
      ),
    };
  }
  throw Error("Unsupported operation");
}
main()
  .then((x) => {
    process.stdout.write(JSON.stringify(x));
    process.exit(0);
  })
  .catch(() => {
    process.stderr.write("ZKP operation failed");
    process.exit(1);
  });
