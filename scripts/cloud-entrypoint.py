"""Initialize the mounted disk directory, then drop privileges before serving."""
import os
import sys
from pathlib import Path

disk = Path('/var/data')
if Path(os.environ.get('ZKP_DB', '/var/data/registry.db')).parent != disk:
    raise SystemExit('The container registry must live on /var/data')
if not os.environ.get('DATABASE_URL'):
    disk.mkdir(parents=True, exist_ok=True)
if os.getuid() == 0:
    if not os.environ.get('DATABASE_URL'):
        os.chown(disk, 10001, 10001)
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
os.environ['HOME'] = '/home/veil'
os.execvp(sys.executable, [sys.executable, '-m', 'uvicorn', 'backend.api:app', '--host', '0.0.0.0', '--port', os.environ.get('PORT', '10000'), '--workers', '1', '--no-access-log'])
