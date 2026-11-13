import os,sys,subprocess,json,secrets,base64
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent

def test_cloud_configuration_and_request_boundaries(tmp_path):
    env=dict(os.environ,ZKP_CLOUD='1',ZKP_PUBLIC_ORIGIN='https://veil.example',ZKP_DB=str(tmp_path/'cloud.db'),ZKP_DATA_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),ZKP_ADMIN_TOKEN=secrets.token_hex(32))
    code='''
import os,json
from fastapi.testclient import TestClient
from backend.api import app
c=TestClient(app,base_url='https://veil.example')
h={'Authorization':'Bearer '+os.environ['ZKP_ADMIN_TOKEN']}
assert c.get('/api/health').json()=={'status':'ok','wallet_mode':'browser'}
assert c.get('/api/admin/state').status_code==401
r=c.get('/api/admin/state',headers=h);assert r.status_code==200
assert 'wasm-unsafe-eval' in r.headers['content-security-policy']
assert c.get('/api/admin/state',headers=dict(h,origin='https://attacker.example')).status_code==403
assert c.get('/api/health',headers={'host':'attacker.example'}).status_code==403
assert c.post('/api/register',content='x'*65537,headers=h).status_code==413
assert c.post('/api/register',content=iter([b'x'*30000,b'x'*40000]),headers=h).status_code==413
assert c.post('/api/register',json={'credential':'must-not-echo'},headers=h).status_code==422
assert c.get('/api/resource/event').status_code==403
assert c.get('/zk/auth_session.wasm').status_code==200
assert c.get('/zk/final.zkey').status_code==200
assert c.get('/zk/input.json').status_code==404
assert c.get('/').status_code==200
print('Cloud configuration, CSP, body limits, private routes and public artifacts passed')
'''
    result=subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,capture_output=True,text=True,timeout=40)
    assert result.returncode==0,result.stdout+result.stderr


def test_cloud_verifier_limits_concurrent_subprocesses(monkeypatch):
    from backend.common import zk, VERIFY_SLOT, VerifierBusy
    import pytest
    monkeypatch.setenv('ZKP_CLOUD','1')
    assert VERIFY_SLOT.acquire(blocking=False)
    try:
        with pytest.raises(VerifierBusy):
            zk('verify',proof={},publicSignals=[])
    finally:
        VERIFY_SLOT.release()
