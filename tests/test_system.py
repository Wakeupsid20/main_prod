import os, base64, secrets, tempfile, json, hashlib, sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

DATA = Path(tempfile.mkdtemp(prefix="veil-tests-"))
os.environ["ZKP_DB"] = str(DATA / "test.db")
os.environ["ZKP_DATA_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ["ZKP_ADMIN_TOKEN"] = secrets.token_hex(32)
os.environ["ZKP_WALLET_TOKEN"] = secrets.token_hex(32)
os.environ["ZKP_WALLET_DIR"] = str(DATA / "wallet")
from backend import api, wallet
from backend.common import zk, seal, unseal, FIELD

client = TestClient(api.app)
wc = TestClient(wallet.app)
ADMIN = {"Authorization": "Bearer " + os.environ["ZKP_ADMIN_TOKEN"]}
HOLDER = {"Authorization": "Bearer " + os.environ["ZKP_WALLET_TOKEN"]}


@pytest.fixture(scope="module")
def person():
    secret = str(secrets.randbelow(FIELD - 1) + 1)
    commitment = zk("commit", credential=secret)["commitment"]
    r = client.post(
        "/api/register",
        headers=ADMIN,
        json={"name": "TEST ONLY", "role": "attendee", "commitment": commitment},
    )
    assert r.status_code == 200
    uid = r.json()["id"]
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": uid, "scenario": "event", "allowed": True},
    )
    return uid, secret, commitment


def challenge(person, scenario="event"):
    r = client.post("/api/challenge", json={"uid": person[0], "scenario": scenario})
    assert r.status_code == 200
    return r.json()


def envelope(person, ch):
    result = zk(
        "prove",
        input={
            "credential": person[1],
            "commitment": person[2],
            "challenge": ch["challenge"],
        },
    )
    return dict(result, challenge_id=ch["id"])


@pytest.fixture(scope="module")
def valid_bundle(person):
    return envelope(person, challenge(person))


def test_valid_registered_credential(person, valid_bundle):
    r = client.post("/api/verify", json=valid_bundle)
    assert r.status_code == 200
    r = client.get(
        "/api/resource/event",
        headers={"Authorization": "Bearer " + r.json()["access_token"]},
    )
    assert r.status_code == 200 and "Assembly entry" in r.json()["data"]


def test_incorrect_credential(person):
    ch = challenge(person)
    with pytest.raises(ValueError):
        zk(
            "prove",
            input={
                "credential": str(int(person[1]) + 1),
                "commitment": person[2],
                "challenge": ch["challenge"],
            },
        )


def test_unregistered_credential():
    secret = str(secrets.randbelow(FIELD - 1) + 1)
    commitment = zk("commit", credential=secret)["commitment"]
    bundle = zk(
        "prove",
        input={"credential": secret, "commitment": commitment, "challenge": "123"},
    )
    # Mathematically valid, but no issuer registry entry or challenge.
    assert zk("verify", **bundle)["valid"]
    assert (
        client.post(
            "/api/verify", json=dict(bundle, challenge_id="unregistered")
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/challenge", json={"uid": "unknown", "scenario": "event"}
        ).status_code
        == 403
    )


def test_reused_proof(valid_bundle):
    assert client.post("/api/verify", json=valid_bundle).status_code == 403


def test_tampered_proof(person):
    b = envelope(person, challenge(person))
    b["proof"]["pi_a"][0] = "1"
    assert client.post("/api/verify", json=b).status_code == 403


def test_challenge_binding(person):
    old = challenge(person)
    b = envelope(person, old)
    fresh = challenge(person)
    b["challenge_id"] = fresh["id"]
    b["publicSignals"][2] = fresh["challenge"]
    assert client.post("/api/verify", json=b).status_code == 403


def test_insufficient_permission(person):
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": person[0], "scenario": "event", "allowed": False},
    )
    r = client.post("/api/verify", json=envelope(person, challenge(person)))
    assert r.status_code == 200
    assert (
        client.get(
            "/api/resource/event",
            headers={"Authorization": "Bearer " + r.json()["access_token"]},
        ).status_code
        == 403
    )
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": person[0], "scenario": "event", "allowed": True},
    )


def test_permission_revocation_existing_session(person):
    r = client.post("/api/verify", json=envelope(person, challenge(person)))
    h = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.get("/api/resource/event", headers=h).status_code == 200
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": person[0], "scenario": "event", "allowed": False},
    )
    assert client.get("/api/resource/event", headers=h).status_code == 403


def test_role_and_scenario_binding(person):
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": person[0], "scenario": "corporate", "allowed": True},
    )
    r = client.post(
        "/api/verify", json=envelope(person, challenge(person, "corporate"))
    )
    assert r.status_code == 200
    h = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.get("/api/resource/corporate", headers=h).status_code == 403
    assert client.get("/api/resource/event", headers=h).status_code == 403


def test_unauthorized_resource_and_admin():
    assert client.get("/api/resource/event").status_code == 403
    assert (
        client.post(
            "/api/register",
            json={"name": "Intruder", "role": "attendee", "commitment": "123"},
        ).status_code
        == 401
    )
    assert client.get("/api/admin/state").status_code == 401
    assert (
        client.post(
            "/wallet/issue",
            json={
                "name": "X",
                "role": "attendee",
                "password": "password12345",
                "admin_token": "a" * 32,
            },
        ).status_code
        == 404
    )
    assert (
        wc.post(
            "/wallet/issue",
            json={
                "name": "X",
                "role": "attendee",
                "password": "password12345",
                "admin_token": "a" * 32,
            },
        ).status_code
        == 401
    )


def test_encryption_decryption_and_tampering():
    key = secrets.token_bytes(32)
    data = b"DUMMY protected resource"
    enc = seal(key, data, b"event")
    assert unseal(key, enc, b"event") == data
    with pytest.raises(ValueError):
        unseal(secrets.token_bytes(32), enc, b"event")
    with pytest.raises(ValueError):
        unseal(key, enc, b"corporate")
    raw = bytearray(base64.b64decode(enc))
    raw[-1] ^= 1
    with pytest.raises(ValueError):
        unseal(key, base64.b64encode(raw).decode(), b"event")


def test_wallet_proof_and_wrong_password(person):
    from Crypto.Protocol.KDF import scrypt

    password = "test-only-passphrase"
    salt = secrets.token_bytes(16)
    key = scrypt(password.encode(), salt, 32, N=32768, r=8, p=1)
    (wallet.DIRECTORY / (person[0] + ".json")).write_text(
        json.dumps(
            {
                "salt": salt.hex(),
                "ciphertext": seal(key, person[1].encode(), person[2].encode()),
                "commitment": person[2],
            }
        )
    )
    ch = challenge(person)
    body = {
        "uid": person[0],
        "password": password,
        "challenge_id": ch["id"],
        "challenge": ch["challenge"],
        "commitment": person[2],
    }
    r = wc.post("/wallet/prove", headers=HOLDER, json=body)
    assert r.status_code == 200
    assert person[1] not in r.text
    assert client.post("/api/verify", json=r.json()).status_code == 200
    body["password"] = "wrong-passphrase"
    assert wc.post("/wallet/prove", headers=HOLDER, json=body).status_code == 400
    assert "proof_generation" in (wallet.DIRECTORY / "events.jsonl").read_text()


def test_expired_challenge(person):
    ch = challenge(person)
    b = envelope(person, ch)
    with api.tx() as c:
        c.execute("UPDATE challenges SET expires=0 WHERE id=?", (ch["id"],))
    assert client.post("/api/verify", json=b).status_code == 403


def test_revoked_credential(person):
    ch = challenge(person)
    b = envelope(person, ch)
    assert (
        client.post("/api/revoke", headers=ADMIN, json={"uid": person[0]}).status_code
        == 200
    )
    assert client.post("/api/verify", json=b).status_code == 403
    assert (
        client.post(
            "/api/challenge", json={"uid": person[0], "scenario": "event"}
        ).status_code
        == 403
    )


def test_audit_integrity():
    with api.tx() as c:
        assert api.integrity(c)
        row = c.execute("SELECT * FROM audit LIMIT 1").fetchone()
        c.execute(
            "UPDATE audit SET record=? WHERE id=?",
            (row["record"].replace("registration", "tampered"), row["id"]),
        )
        assert not api.integrity(c)
        c.execute("UPDATE audit SET record=? WHERE id=?", (row["record"], row["id"]))
        assert api.integrity(c)
    state = client.get("/api/admin/state", headers=ADMIN).json()
    assert state["integrity"]
    assert "credential" not in state  # no private credential fields


@pytest.mark.parametrize(
    "scenario,role",
    [
        ("healthcare", "doctor"),
        ("university", "student"),
        ("corporate", "employee"),
        ("event", "attendee"),
    ],
)
def test_each_scenario(scenario, role):
    secret = str(secrets.randbelow(FIELD - 1) + 1)
    commitment = zk("commit", credential=secret)["commitment"]
    r = client.post(
        "/api/register",
        headers=ADMIN,
        json={"name": "Scenario TEST", "role": role, "commitment": commitment},
    )
    assert r.status_code == 200
    user = (r.json()["id"], secret, commitment)
    client.post(
        "/api/permission",
        headers=ADMIN,
        json={"uid": user[0], "scenario": scenario, "allowed": True},
    )
    r = client.post("/api/verify", json=envelope(user, challenge(user, scenario)))
    assert r.status_code == 200
    h = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.get("/api/resource/" + scenario, headers=h).status_code == 200
    client.post("/api/revoke", headers=ADMIN, json={"uid": user[0]})
    assert client.get("/api/resource/" + scenario, headers=h).status_code == 403


def test_expired_access_session():
    token = secrets.token_urlsafe(32)
    with api.tx() as c:
        u = c.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
        c.execute(
            "INSERT INTO sessions VALUES (?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), u, "event", 0),
        )
    assert (
        client.get(
            "/api/resource/event", headers={"Authorization": "Bearer " + token}
        ).status_code
        == 403
    )


def test_artifact_validation():
    from backend.common import validate_artifacts

    validate_artifacts()


def test_validation_errors_do_not_echo_secrets():
    secret = "test-sensitive-value"
    r = client.post('/api/register', headers=ADMIN, json={'credential': secret})
    assert r.status_code == 422 and secret not in r.text
    r = wc.post('/wallet/issue', headers=HOLDER, json={'password': secret})
    assert r.status_code == 422 and secret not in r.text
