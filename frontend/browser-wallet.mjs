// This holder module runs on the user's device. Never send secrets to the API.
import { poseidon1 } from "poseidon-lite/poseidon1";

export const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PREFIX = "veil-wallet-v1:";
const encoder = new TextEncoder();
const ITERATIONS = 600000;
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
function requireCrypto() {
  if (!globalThis.crypto?.subtle)
    throw Error("The browser wallet requires HTTPS or localhost.");
}
export function randomCredential() {
  requireCrypto();
  for (;;) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const n = BigInt(
      "0x" + [...bytes].map((x) => x.toString(16).padStart(2, "0")).join(""),
    );
    if (n > 0n && n < FIELD) return n.toString();
  }
}
export function commitmentOf(secret) {
  const n = BigInt(secret);
  if (n <= 0n || n >= FIELD) throw Error("Invalid credential field element.");
  return poseidon1([n]).toString();
}
async function derive(password, salt) {
  requireCrypto();
  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 200
  )
    throw Error("Use a passphrase of 12 to 200 characters.");
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function encryptCredential(secret, password) {
  const commitment = commitmentOf(secret);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derive(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(commitment) },
    key,
    encoder.encode(secret),
  );
  return {
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: ITERATIONS,
    salt: b64(salt),
    iv: b64(iv),
    ciphertext: b64(ciphertext),
    commitment,
  };
}
export function validateWallet(item) {
  if (
    !item ||
    item.version !== 1 ||
    item.kdf !== "PBKDF2-SHA256" ||
    item.iterations !== ITERATIONS ||
    !/^[0-9]{1,77}$/.test(item.commitment)
  )
    throw Error("Unsupported encrypted wallet format.");
  if (
    unb64(item.salt).length !== 16 ||
    unb64(item.iv).length !== 12 ||
    unb64(item.ciphertext).length > 256
  )
    throw Error("Invalid encrypted wallet.");
  if (BigInt(item.commitment) <= 0n || BigInt(item.commitment) >= FIELD)
    throw Error("Invalid commitment.");
}
export async function decryptCredential(item, password) {
  validateWallet(item);
  try {
    const key = await derive(password, unb64(item.salt));
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(item.iv),
        additionalData: encoder.encode(item.commitment),
      },
      key,
      unb64(item.ciphertext),
    );
    const secret = new TextDecoder().decode(plain);
    if (commitmentOf(secret) !== item.commitment) throw Error();
    return secret;
  } catch {
    throw Error(
      "Wallet unlock failed. Check the passphrase and encrypted backup.",
    );
  }
}
export async function issueInBrowser({
  name,
  role,
  password,
  register,
  storage = localStorage,
}) {
  const secret = randomCredential();
  const item = await encryptCredential(secret, password);
  const pending = PREFIX + "pending:" + crypto.randomUUID();
  // Persist the encrypted holder record before enrollment. No plaintext secret storage.
  storage.setItem(pending, JSON.stringify(item));
  const user = await register({ name, role, commitment: item.commitment });
  storage.setItem(PREFIX + user.id, JSON.stringify(item));
  storage.removeItem(pending);
  return user;
}
export async function proveInBrowser({
  uid,
  password,
  challenge,
  storage = localStorage,
  prover,
}) {
  const raw = storage.getItem(PREFIX + uid);
  if (!raw)
    throw Error(
      "No wallet on this browser. Import its encrypted backup or register here.",
    );
  const item = JSON.parse(raw);
  if (item.commitment !== challenge.commitment)
    throw Error("Wallet and issuer commitment differ.");
  const secret = await decryptCredential(item, password);
  const groth16 = prover ?? (await import("snarkjs")).groth16;
  const result = await groth16.fullProve(
    {
      credential: secret,
      commitment: item.commitment,
      challenge: challenge.challenge,
    },
    "/zk/auth_session.wasm",
    "/zk/final.zkey",
    undefined,
    undefined,
    { singleThread: true },
  );
  return { ...result, challenge_id: challenge.id };
}
export function walletBackup(uid, storage = localStorage) {
  if (!/^[a-f0-9]{24}$/.test(uid)) throw Error("Select a registered identity.");
  const raw = storage.getItem(PREFIX + uid);
  if (!raw) throw Error("This identity has no wallet in this browser.");
  const item = JSON.parse(raw);
  validateWallet(item);
  return JSON.stringify(
    { format: "veil-browser-wallet", uid, wallet: item },
    null,
    2,
  );
}
export function importWallet(text, storage = localStorage) {
  if (text.length > 4096) throw Error("Wallet backup is too large.");
  const backup = JSON.parse(text);
  if (
    backup.format !== "veil-browser-wallet" ||
    !/^[a-f0-9]{24}$/.test(backup.uid)
  )
    throw Error("Invalid wallet backup.");
  validateWallet(backup.wallet);
  if (storage.getItem(PREFIX + backup.uid))
    throw Error("A wallet already exists for this identity in this browser.");
  storage.setItem(PREFIX + backup.uid, JSON.stringify(backup.wallet));
  return backup.uid;
}
