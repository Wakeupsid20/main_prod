import os,sys,secrets,base64,subprocess,time,tempfile,json
from pathlib import Path
import httpx
root=Path(__file__).resolve().parent.parent
data=Path(tempfile.mkdtemp(prefix='veil-http-tests-'))
env=dict(os.environ,ZKP_DB=str(data/'registry.db'),ZKP_WALLET_DIR=str(data/'wallet'),ZKP_DATA_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),ZKP_ADMIN_TOKEN=secrets.token_hex(32),ZKP_WALLET_TOKEN=secrets.token_hex(32))
logs=(data/'servers.log').open('w')
processes=[subprocess.Popen([sys.executable,'-m','uvicorn',app,'--host','127.0.0.1','--port',port,'--no-access-log'],cwd=root,env=env,stdout=logs,stderr=logs) for app,port in [('backend.api:app','8000'),('backend.wallet:app','8001')]]
try:
 with httpx.Client(timeout=180,trust_env=False) as c:
  for _ in range(60):
   try:
    if c.get('http://127.0.0.1:8000/').status_code==200 and c.get('http://127.0.0.1:8001/').status_code==404:break
   except httpx.ConnectError:pass
   time.sleep(.5)
  else:raise RuntimeError('Services did not start')
  admin={'Authorization':'Bearer '+env['ZKP_ADMIN_TOKEN']};holder={'Authorization':'Bearer '+env['ZKP_WALLET_TOKEN']};results=[]
  def post(base,path,body,headers={}):
   r=c.post(base+path,json=body,headers=headers);assert r.status_code==200,(path,r.status_code,r.text);return r.json()
  api='http://127.0.0.1:8000';wallet='http://127.0.0.1:8001'
  for scenario,role in [('healthcare','doctor'),('university','student'),('corporate','employee'),('event','attendee')]:
   user=post(wallet,'/wallet/issue',{'name':'HTTP TEST '+role,'role':role,'password':'test-only-passphrase','admin_token':env['ZKP_ADMIN_TOKEN']},holder)
   assert 'credential' not in user
   uid=user['id'];post(api,'/api/permission',{'uid':uid,'scenario':scenario,'allowed':True},admin)
   ch=post(api,'/api/challenge',{'uid':uid,'scenario':scenario})
   bundle=post(wallet,'/wallet/prove',{'uid':uid,'password':'test-only-passphrase','challenge_id':ch['id'],'challenge':ch['challenge'],'commitment':ch['commitment']},holder)
   session=post(api,'/api/verify',bundle)
   r=c.get(api+'/api/resource/'+scenario,headers={'Authorization':'Bearer '+session['access_token']});assert r.status_code==200
   assert c.post(api+'/api/verify',json=bundle).status_code==403
   results.append({'scenario':scenario,'issuance':'passed','proof':'passed','resource':'passed','replay_rejection':'passed'})
  report={'real_http_integration':results,'dummy_data_only':True}
  (root/'http-test-results.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)

finally:
 for process in processes:process.terminate()
 for process in processes:process.wait(timeout=15)
 logs.close()
