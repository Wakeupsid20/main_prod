import hashlib, hmac, json, os, secrets, sqlite3, time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from threading import Lock
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from .common import ROOT, FIELD, SCENARIOS, zk, seal, unseal, envkey, validate_artifacts, VerifierBusy

validate_artifacts()
app = FastAPI(title="Veil / Issuer and verifier", docs_url=None, redoc_url=None)
CLOUD = os.environ.get('ZKP_CLOUD') == '1'
ORIGINS = {'http://127.0.0.1:8000', 'http://localhost:8000'} if not CLOUD else set()
HOSTS = {'127.0.0.1', 'localhost', 'testserver'} if not CLOUD else {'127.0.0.1', 'localhost'}
if not CLOUD and os.environ.get('ZKP_DEV_ORIGIN'):
    dev_origin=os.environ['ZKP_DEV_ORIGIN'].rstrip('/')
    dev_url=urlsplit(dev_origin)
    if dev_url.scheme not in ('http','https') or dev_url.hostname not in ('localhost','127.0.0.1') or dev_url.path:
        raise ValueError('Development origin must be loopback only')
    ORIGINS.add(dev_origin)
public_origin = os.environ.get('ZKP_PUBLIC_ORIGIN', '').rstrip('/')
render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME', '')
if render_host:
    HOSTS.add(render_host)
    ORIGINS.add('https://' + render_host)
if public_origin:
    parsed = urlsplit(public_origin)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError('ZKP_PUBLIC_ORIGIN must be an HTTPS origin without a path')
    HOSTS.add(parsed.hostname)
    ORIGINS.add(public_origin)
if CLOUD and not ORIGINS:
    raise ValueError('Cloud mode requires RENDER_EXTERNAL_HOSTNAME or ZKP_PUBLIC_ORIGIN')


@app.exception_handler(RequestValidationError)
async def invalid_request(request, error):
    # Pydantic's default errors can echo submitted sensitive values.
    return JSONResponse({"detail": "Invalid request fields"}, status_code=422)


LOCK = Lock()
DB = Path(os.environ.get("ZKP_DB", ROOT / "data/registry.db"))
KEY = envkey()
ADMIN = os.environ["ZKP_ADMIN_TOKEN"]
if len(ADMIN) < 32:
    raise ValueError("Use a random administrator token of at least 32 characters")
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import UniqueViolation
    if urlsplit(DATABASE_URL).scheme not in ("postgres", "postgresql"):
        raise ValueError("DATABASE_URL must be a PostgreSQL connection URL")
    integrity_errors = (UniqueViolation,)
else:
    DB.parent.mkdir(parents=True, exist_ok=True)
    integrity_errors = (sqlite3.IntegrityError,)


class PostgresConnection(psycopg.Connection if DATABASE_URL else object):
    def execute(self, query, params=None):
        return super().execute(query.replace("?", "%s"), params)



def connect():
    if DATABASE_URL:
        return PostgresConnection.connect(DATABASE_URL, row_factory=dict_row, sslmode="require", connect_timeout=10)
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c


@contextmanager
def tx():
    with LOCK:
        c = connect()
        try:
            if DATABASE_URL:
                c.execute("SELECT pg_advisory_xact_lock(78539612)")
            else:
                c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except:
            c.rollback()
            raise
        finally:
            c.close()


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def audit(c, event, subject="", outcome="ok"):
    prev = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    record = {
        "time": time.time(),
        "event": event,
        "subject": subject,
        "outcome": outcome,
        "previous": prev["hash"] if prev else "0" * 64,
    }
    digest = hmac.new(KEY, canonical(record).encode(), hashlib.sha256).hexdigest()
    c.execute(
        "INSERT INTO audit(record,hash) VALUES (?,?)", (canonical(record), digest)
    )


def integrity(c):
    prev = "0" * 64
    for r in c.execute("SELECT * FROM audit ORDER BY id"):
        obj = json.loads(r["record"])
        if obj["previous"] != prev or not hmac.compare_digest(
            r["hash"],
            hmac.new(KEY, canonical(obj).encode(), hashlib.sha256).hexdigest(),
        ):
            return False
        prev = r["hash"]
    return True


with tx() as c:
    schema = """CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,role TEXT,commitment TEXT UNIQUE,revoked INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS grants(uid TEXT,scenario TEXT,allowed INTEGER,PRIMARY KEY(uid,scenario));
 CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,uid TEXT,scenario TEXT,nonce TEXT,expires REAL,used INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid TEXT,scenario TEXT,expires REAL);
 CREATE TABLE IF NOT EXISTS resources(scenario TEXT PRIMARY KEY,ciphertext TEXT);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,record TEXT,hash TEXT);"""
    if DATABASE_URL:
        schema = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("expires REAL", "expires DOUBLE PRECISION")
    for statement in schema.split(";"):
        if statement.strip():
            c.execute(statement)
    for scenario, (_, text) in SCENARIOS.items():
        c.execute(
            "INSERT INTO resources VALUES (?,?) ON CONFLICT(scenario) DO NOTHING",
            (scenario, seal(KEY, text.encode(), scenario.encode())),
        )


@app.middleware("http")
async def local_only(request: Request, call_next):
    if request.url.hostname not in HOSTS:


        return JSONResponse({"detail": "Invalid host"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and origin not in ORIGINS:


        return JSONResponse({"detail": "Invalid origin"}, status_code=403)
    if request.method in ('POST', 'PUT', 'PATCH'):
        chunks=[]
        size=0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 65536:
                return JSONResponse({'detail':'Request body too large'},status_code=413)
            chunks.append(chunk)
        request._body = b''.join(chunks)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if CLOUD:
        response.headers['Strict-Transport-Security']='max-age=31536000'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    return response


@app.get('/api/health')
def health():
    return {'status':'ok','wallet_mode':'browser' if CLOUD else 'local'}


def admin(authorization: str = Header(default="")):
    if not hmac.compare_digest(authorization, "Bearer " + ADMIN):
        raise HTTPException(401, "Administrator authorization required")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Registration(Strict):
    name: str = Field(min_length=1, max_length=80)
    role: str
    commitment: str = Field(pattern=r"^[0-9]{1,77}$")


@app.post("/api/register", dependencies=[Depends(admin)])
def register(b: Registration):
    if (
        b.role not in [x[0] for x in SCENARIOS.values()]
        or not 0 < int(b.commitment) < FIELD
    ):
        raise HTTPException(400, "Invalid role or field commitment")
    uid = secrets.token_hex(12)
    try:
        with tx() as c:
            c.execute(
                "INSERT INTO users(id,name,role,commitment) VALUES (?,?,?,?)",
                (uid, b.name, b.role, b.commitment),
            )
            audit(c, "registration", uid)
            audit(c, "credential_issued", uid)
    except integrity_errors:
        raise HTTPException(409, "Commitment already registered")
    return {"id": uid, "commitment": b.commitment}


class Permission(Strict):
    uid: str
    scenario: str
    allowed: bool


@app.post("/api/permission", dependencies=[Depends(admin)])
def permission(b: Permission):
    with tx() as c:
        if (
            b.scenario not in SCENARIOS
            or not c.execute("SELECT 1 FROM users WHERE id=?", (b.uid,)).fetchone()
        ):
            raise HTTPException(404, "Unknown user or scenario")
        c.execute(
            "INSERT INTO grants VALUES (?,?,?) ON CONFLICT(uid,scenario) DO UPDATE SET allowed=excluded.allowed",
            (b.uid, b.scenario, int(b.allowed)),
        )
        audit(c, "permission_granted" if b.allowed else "permission_revoked", b.uid)
    return {"ok": True}


class Revoke(Strict):
    uid: str


@app.post("/api/revoke", dependencies=[Depends(admin)])
def revoke(b: Revoke):
    with tx() as c:
        if not c.execute("UPDATE users SET revoked=1 WHERE id=?", (b.uid,)).rowcount:
            raise HTTPException(404, "Unknown user")
        audit(c, "credential_revoked", b.uid)
    return {"ok": True}


class Challenge(Strict):
    uid: str = Field(max_length=80)
    scenario: str


@app.post("/api/challenge")
def challenge(b: Challenge):
    if b.scenario not in SCENARIOS:
        raise HTTPException(400, "Unknown scenario")
    with tx() as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (b.uid,)).fetchone()
        if not u or u["revoked"]:
            audit(c, "challenge_denied", b.uid, "denied")
            result = None
        else:
            cid = secrets.token_hex(24)
            nonce = str(secrets.randbelow(FIELD - 1) + 1)
            expires = time.time() + 120
            c.execute(
                "INSERT INTO challenges(id,uid,scenario,nonce,expires) VALUES (?,?,?,?,?)",
                (cid, b.uid, b.scenario, nonce, expires),
            )
            audit(c, "challenge_issued", b.uid)
            result = {
                "id": cid,
                "challenge": nonce,
                "commitment": u["commitment"],
                "expires": expires,
            }
    if not result:
        raise HTTPException(403, "Unknown or revoked credential")
    return result


class Verification(Strict):
    challenge_id: str = Field(max_length=80)
    proof: dict
    publicSignals: list[str] = Field(min_length=3, max_length=3)


@app.post("/api/verify")
def verify(b: Verification):
    # Consume before expensive verification, atomically; attempts cannot race or reuse challenges.
    with tx() as c:
        ch = c.execute(
            "SELECT * FROM challenges WHERE id=?", (b.challenge_id,)
        ).fetchone()
        if not ch or ch["used"] or ch["expires"] < time.time():
            audit(c, "verification_denied", "", "stale_or_reused")
            ch = None
        else:
            c.execute("UPDATE challenges SET used=1 WHERE id=?", (b.challenge_id,))
    if ch is None:
        raise HTTPException(403, "Challenge expired, unknown or already consumed")
    valid = False
    busy = False
    try:
        with connect() as c:
            u = c.execute("SELECT * FROM users WHERE id=?", (ch["uid"],)).fetchone()
        valid = bool(
            u
            and not u["revoked"]
            and b.publicSignals[1:] == [u["commitment"], ch["nonce"]]
            and zk("verify", proof=b.proof, publicSignals=b.publicSignals)["valid"]
        )
    except VerifierBusy:
        busy = True
    except (ValueError, KeyError, TimeoutError):
        pass
    with tx() as c:
        # Recheck revocation after expensive pairing verification.
        u = c.execute("SELECT * FROM users WHERE id=?", (ch["uid"],)).fetchone()
        valid = valid and u and not u["revoked"]
        audit(
            c,
            "proof_verified" if valid else "verification_denied",
            ch["uid"],
            "ok" if valid else "invalid",
        )
        if valid:
            token = secrets.token_urlsafe(32)
            c.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    ch["uid"],
                    ch["scenario"],
                    time.time() + 180,
                ),
            )
    if not valid:
        if busy:
            raise HTTPException(503, 'Verifier busy. Generate a fresh proof and retry shortly.')
        raise HTTPException(403, "Proof invalid or credential revoked")
    return {"verified": True, "access_token": token, "expires_in": 180}


@app.get("/api/resource/{scenario}")
def resource(scenario: str, authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ")
    with tx() as c:
        s = c.execute(
            "SELECT s.*,u.role,u.revoked FROM sessions s JOIN users u ON u.id=s.uid WHERE s.token=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        grant = c.execute(
            "SELECT allowed FROM grants WHERE uid=? AND scenario=?",
            (s["uid"] if s else "", scenario),
        ).fetchone()
        ok = (
            s
            and scenario in SCENARIOS
            and s["scenario"] == scenario
            and s["expires"] > time.time()
            and not s["revoked"]
            and s["role"] == SCENARIOS[scenario][0]
            and grant
            and grant["allowed"]
        )
        audit(
            c,
            "access_granted" if ok else "access_denied",
            s["uid"] if s else "",
            scenario,
        )
        result = (
            unseal(
                KEY,
                c.execute(
                    "SELECT ciphertext FROM resources WHERE scenario=?", (scenario,)
                ).fetchone()["ciphertext"],
                scenario.encode(),
            ).decode()
            if ok
            else None
        )
    if result is None:
        raise HTTPException(
            403,
            "Access denied: fresh proof, matching role and explicit permission required",
        )
    return {"data": result}


@app.get("/api/admin/state", dependencies=[Depends(admin)])
def state():
    with connect() as c:
        events = [
            dict(json.loads(r["record"]), hash=r["hash"])
            for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")
        ]
        counts = {
            r["event"]: r["n"]
            for r in c.execute(
                ("SELECT record::jsonb->>'event' AS event,count(*) AS n FROM audit GROUP BY 1" if DATABASE_URL else "SELECT json_extract(record,'$.event') event,count(*) n FROM audit GROUP BY event")
            )
        }
        return {
            "users": [dict(r) for r in c.execute("SELECT * FROM users")],
            "grants": [dict(r) for r in c.execute("SELECT * FROM grants")],
            "events": events,
            "integrity": integrity(c),
            "counts": counts,
        }


if (ROOT / "dist").exists():
    app.mount("/assets", StaticFiles(directory=ROOT / "dist/assets"), name="assets")
    if (ROOT / 'dist/zk').exists():
        app.mount('/zk', StaticFiles(directory=ROOT/'dist/zk'), name='public-proving-artifacts')

    @app.get("/")
    def index():
        return FileResponse(ROOT / "dist/index.html")

