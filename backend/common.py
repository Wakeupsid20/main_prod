import base64, json, os, subprocess
from threading import BoundedSemaphore
from pathlib import Path
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parent.parent
VERIFY_SLOT = BoundedSemaphore(1)


class VerifierBusy(Exception):
    pass
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SCENARIOS = {
    "healthcare": (
        "doctor",
        "Authorized dummy patient record: PAT-DEMO; routine checkup.",
    ),
    "university": ("student", "Restricted student service: demo enrollment confirmed."),
    "corporate": ("employee", "Restricted area: demo laboratory entry authorized."),
    "event": ("attendee", "Assembly entry: demo seat A-12."),
}


def zk(op, **kwargs):
    limited = op == 'verify' and os.environ.get('ZKP_CLOUD') == '1'
    if limited and not VERIFY_SLOT.acquire(blocking=False):
        raise VerifierBusy('Verifier is busy')
    try:
        r = subprocess.run(
            ["node", str(ROOT / "zk.cjs")],
            input=json.dumps(dict(op=op, **kwargs)),
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=180,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("Cryptographic operation timed out") from error
    finally:
        if limited:
            VERIFY_SLOT.release()
    if r.returncode:
        raise ValueError("Cryptographic operation rejected")
    return json.loads(r.stdout)


def seal(key, data, aad=b""):
    c = AES.new(key, AES.MODE_GCM)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(data)
    return base64.b64encode(c.nonce + tag + ct).decode()


def unseal(key, data, aad=b""):
    raw = base64.b64decode(data)
    c = AES.new(key, AES.MODE_GCM, nonce=raw[:16])
    c.update(aad)
    return c.decrypt_and_verify(raw[32:], raw[16:32])


def envkey():
    key = base64.b64decode(os.environ["ZKP_DATA_KEY"], validate=True)
    if len(key) != 32:
        raise ValueError("ZKP_DATA_KEY must encode 32 bytes")
    return key


def validate_artifacts():
    import hashlib

    directory = ROOT / "build/session"
    manifest = json.loads((directory / "manifest.json").read_text())
    digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    if manifest["circuit"] != digest(ROOT / "auth_session.circom"):
        raise RuntimeError("Circuit changed: regenerate ZKP setup")
    for name, expected in manifest["files"].items():
        if digest(directory / name) != expected:
            raise RuntimeError("ZKP artifacts changed: verify setup provenance")
