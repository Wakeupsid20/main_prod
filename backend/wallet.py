# Separate holder process: verifier API never accepts the private credential.
import hashlib, hmac, json, os, secrets, time
from threading import Lock
from pathlib import Path
import httpx
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ConfigDict
from Crypto.Protocol.KDF import scrypt
from .common import ROOT, FIELD, zk, seal, unseal, validate_artifacts

validate_artifacts()
app = FastAPI(title="Local encrypted holder wallet", docs_url=None, redoc_url=None)


@app.exception_handler(RequestValidationError)
async def invalid_request(request, error):
    return JSONResponse({"detail": "Invalid request fields"}, status_code=422)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["POST"],
    allow_headers=["Content-Type", "Authorization"],
)
AUDIT_LOCK = Lock()


def holder_event(uid, outcome):
    from .common import envkey

    with AUDIT_LOCK:
        target = DIRECTORY / "events.jsonl"
        lines = target.read_text().splitlines() if target.exists() else []
        previous = json.loads(lines[-1])["hash"] if lines else "0" * 64
        entry = {
            "time": time.time(),
            "event": "proof_generation",
            "subject": uid,
            "outcome": outcome,
            "previous": previous,
        }
        entry["hash"] = hmac.new(
            envkey(), json.dumps(entry, sort_keys=True).encode(), hashlib.sha256
        ).hexdigest()
        with target.open("a") as f:
            f.write(json.dumps(entry) + "\n")


TOKEN = os.environ["ZKP_WALLET_TOKEN"]
DIRECTORY = Path(os.environ.get("ZKP_WALLET_DIR", ROOT / "data/wallet"))
DIRECTORY.mkdir(parents=True, exist_ok=True)


def auth(authorization: str = Header(default="")):
    if not hmac.compare_digest(authorization, "Bearer " + TOKEN):
        raise HTTPException(401, "Holder wallet authorization required")


class Issue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    role: str
    password: str = Field(min_length=12, max_length=200)
    admin_token: str = Field(min_length=32, max_length=200)


@app.post("/wallet/issue", dependencies=[Depends(auth)])
def issue(b: Issue):
    secret = str(secrets.randbelow(FIELD - 1) + 1)
    commitment = zk("commit", credential=secret)["commitment"]
    salt = secrets.token_bytes(16)
    key = scrypt(b.password.encode(), salt, 32, N=32768, r=8, p=1)
    # Save pending encrypted wallet before registration; no credential loss on failed response.
    pending = DIRECTORY / (secrets.token_hex(16) + ".pending")
    pending.write_text(
        json.dumps(
            {
                "salt": salt.hex(),
                "ciphertext": seal(key, secret.encode(), commitment.encode()),
                "commitment": commitment,
            }
        )
    )
    with httpx.Client(timeout=30, trust_env=False) as c:
        r = c.post(
            "http://127.0.0.1:8000/api/register",
            json={"name": b.name, "role": b.role, "commitment": commitment},
            headers={"Authorization": "Bearer " + b.admin_token},
        )
    if r.status_code != 200:
        raise HTTPException(
            r.status_code,
            "Issuer rejected registration; encrypted pending wallet retained",
        )
    user = r.json()
    pending.rename(DIRECTORY / (user["id"] + ".json"))
    return user


class Prove(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(pattern=r"^[a-f0-9]{24}$")
    password: str = Field(min_length=12, max_length=200)
    challenge_id: str
    challenge: str = Field(pattern=r"^[0-9]{1,77}$")
    commitment: str = Field(pattern=r"^[0-9]{1,77}$")


@app.post("/wallet/prove", dependencies=[Depends(auth)])
def prove(b: Prove):
    try:
        item = json.loads((DIRECTORY / (b.uid + ".json")).read_text())
        key = scrypt(
            b.password.encode(), bytes.fromhex(item["salt"]), 32, N=32768, r=8, p=1
        )
        secret = unseal(key, item["ciphertext"], item["commitment"].encode()).decode()
        if item["commitment"] != b.commitment:
            raise ValueError()
        result = zk(
            "prove",
            input={
                "credential": secret,
                "commitment": b.commitment,
                "challenge": b.challenge,
            },
        )
        holder_event(b.uid, "ok")
        return dict(result, challenge_id=b.challenge_id)
    except (ValueError, FileNotFoundError):
        holder_event(b.uid, "denied")
        raise HTTPException(400, "Wallet unlock or proof generation failed")
