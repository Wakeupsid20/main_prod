# Render variant validation

Date: 13 November 2026.

- Final Python regression and cloud suite: 24 passed, one Starlette test-client deprecation warning, approximately 49.02 seconds.
- Browser-wallet Node suite: 5 passed. Includes exact commitment parity with circomlibjs, random field credentials, AES-GCM unlock and tamper rejection, secret-free registration payloads, encrypted backup round-trip, a real Groth16 proof and cloud verifier acceptance.
- Cloud frontend build: passed with the browser holder enabled.
- Original local frontend build: passed and restored as the project's current local dist output.
- Isolated actual-browser workflow: registration, browser proof generation, API verification, denial before grant, allowed resource after grant, permission revocation and proof replay rejection all observed.
- Cloud request checks: exact hosts/origins, CSP, HSTS configuration, streamed 64 KiB body limit, protected routes, public proving artifacts and serialized verifier execution passed.
- The saved proof artifacts match their manifest. Git attributes preserve exact manifest-sensitive bytes.
- Local Docker image build: not executed because Docker Desktop's Linux engine is not running.
- Render build, disk mount and live HTTPS workflow: not yet executed. They require a repository, confirmed workspace and approval of the actual paid-resource plan.

The earlier report, video and PowerPoint describe the original local Python wallet. The cloud variant uses browser Web Crypto PBKDF2-SHA256 rather than the original local scrypt wallet file format. See CLOUD_DEPLOYMENT.md. Private source state is excluded from the cloud archive.
