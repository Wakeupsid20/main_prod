import React, { useState as S } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import {
  issueInBrowser,
  proveInBrowser,
  walletBackup,
  importWallet,
} from "./browser-wallet.mjs";
const BROWSER_WALLET = import.meta.env.VITE_WALLET_MODE === "browser";
const scenes = {
  healthcare: ["Healthcare", "doctor", "Patient records"],
  university: ["University", "student", "Student services"],
  corporate: ["Corporate", "employee", "Restricted laboratory"],
  event: ["Event & assembly", "attendee", "Assembly entry"],
};
function App() {
  const [tab, T] = S("Overview"),
    [scenario, SC] = S("event"),
    [admin, A] = S(""),
    [holder, H] = S(""),
    [password, P] = S(""),
    [name, N] = S(""),
    [role, R] = S("attendee"),
    [uid, U] = S(""),
    [state, ST] = S({ users: [], grants: [], events: [], counts: {} }),
    [proof, PR] = S(null),
    [proofText, PT] = S(""),
    [access, AC] = S(""),
    [result, RES] = S("Ready. Connect your local issuer and wallet to begin."),
    [busy, B] = S(false),
    [step, STEP] = S(0);
  async function request(path, body, token = admin, wallet = false) {
    const r = await fetch((wallet ? "http://127.0.0.1:8001" : "") + path, {
      method: body ? "POST" : "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    let j = await r.json();
    if (!r.ok) throw Error(j.detail || "Request rejected");
    return j;
  }
  async function refresh() {
    ST(await request("/api/admin/state"));
  }
  async function run(fn) {
    B(true);
    try {
      await fn();
    } catch (e) {
      RES("Denied / " + e.message);
    } finally {
      B(false);
    }
  }
  function selectUser(v) {
    U(v);
    PR(null);
    PT("");
    AC("");
    STEP(0);
  }
  async function issue() {
    const j = BROWSER_WALLET
      ? await issueInBrowser({
          name,
          role,
          password,
          register: (body) => request("/api/register", body),
        })
      : await request(
          "/wallet/issue",
          { name, role, password, admin_token: admin },
          holder,
          true,
        );
    selectUser(j.id);
    STEP(2);
    RES(
      BROWSER_WALLET
        ? "Credential issued and encrypted in this browser. Download an encrypted wallet backup now. Your passphrase never went to the server."
        : "Credential issued. Only its public commitment was sent to the issuer; the secret is encrypted in your local wallet.",
    );
    await refresh();
  }
  async function generate() {
    AC("");
    const ch = await request("/api/challenge", { uid, scenario }, "");
    const j = BROWSER_WALLET
      ? await proveInBrowser({ uid, password, challenge: ch })
      : await request(
          "/wallet/prove",
          {
            uid,
            password,
            challenge_id: ch.id,
            challenge: ch.challenge,
            commitment: ch.commitment,
          },
          holder,
          true,
        );
    PR(j);
    PT(JSON.stringify(j, null, 2));
    STEP(3);
    RES(
      "Real Groth16 proof generated. Submit it before the challenge expires. A new proof uses a new challenge.",
    );
    await refresh();
  }
  async function verify() {
    AC("");
    const j = await request("/api/verify", JSON.parse(proofText), "");
    AC(j.access_token);
    STEP(4);
    RES(
      "Proof verified. A short-lived session is ready for a separate authorization check.",
    );
    await refresh();
  }
  async function open() {
    try {
      const j = await request("/api/resource/" + scenario, null, access);
      STEP(6);
      RES(j.data);
    } finally {
      await refresh();
    }
  }
  const c = state.counts;
  const attempts = (c.proof_verified || 0) + (c.verification_denied || 0);
  const button = (text, fn, disabled = false, kind = "") => (
    <button
      className={kind}
      disabled={busy || disabled}
      onClick={() => run(fn)}
    >
      {text}
    </button>
  );
  return (
    <div className="shell">
      <aside>
        <a className="brand" onClick={() => T("Overview")}>
          <span className="mark">◈</span> veil<span className="dot">.</span>
        </a>
        <div className="tag">IDENTITY WITHOUT EXPOSURE</div>
        <nav>
          {[
            "Overview",
            "Registration",
            "Credential Wallet",
            "Verification Portal",
            "Access Control",
            "Audit Logs",
          ].map((v, i) => (
            <button
              key={v}
              className={tab === v ? "active" : ""}
              onClick={() => T(v)}
            >
              <span>0{i + 1}</span>
              {v}
            </button>
          ))}
        </nav>
        <div className="side-note">
          <i />
          {BROWSER_WALLET
            ? "CLOUD RESEARCH PROTOTYPE"
            : "LOCAL RESEARCH PROTOTYPE"}
          <p>
            Groth16 · BN254
            <br />
            Poseidon · AES-256-GCM
          </p>
          <small>
            Trusted issuance establishes eligibility. A ZKP proves credential
            possession.
          </small>
        </div>
      </aside>
      <main>
        <header>
          <span>
            RESEARCH CONSOLE <b>/ {tab}</b>
          </span>
          <span className="pill">
            <i /> {BROWSER_WALLET ? "BROWSER WALLET" : "LOCAL ENVIRONMENT"}
          </span>
        </header>
        <section className="heading">
          <div className="eyebrow">PRIVACY-PRESERVING ACCESS CONTROL</div>
          <h1>
            {tab === "Overview" ? (
              <>
                Trust the proof.
                <br />
                <em>Protect the identity.</em>
              </>
            ) : (
              tab
            )}
          </h1>
          <p>A single cryptographic workflow. Four real-world contexts.</p>
          <select
            value={scenario}
            onChange={(e) => {
              SC(e.target.value);
              AC("");
              PR(null);
              PT("");
              STEP(0);
            }}
          >
            {Object.entries(scenes).map(([k, v]) => (
              <option key={k} value={k}>
                {v[0]}
              </option>
            ))}
          </select>
        </section>
        <div className="stats">
          {[
            ["REGISTERED IDENTITIES", state.users.length],
            ["PROOF ATTEMPTS", attempts],
            ["VERIFIED PROOFS", c.proof_verified || 0],
            ["ACCESS DENIALS", c.access_denied || 0],
          ].map(([k, v]) => (
            <article key={k}>
              <span>{k}</span>
              <strong>{String(v).padStart(2, "0")}</strong>
              <small>
                {k === "REGISTERED IDENTITIES"
                  ? "Issuer-controlled registry"
                  : "Recorded by the verifier"}
              </small>
            </article>
          ))}
        </div>
        <section className="workflow">
          {[
            "Register",
            "Issue credential",
            "Generate proof",
            "Verify proof",
            "Authorize",
            "Access",
          ].map((x, i) => (
            <div className={step >= i + 1 ? "done" : ""} key={x}>
              <span>
                {step >= i + 1 ? "✓" : String(i + 1).padStart(2, "0")}
              </span>
              {x}
            </div>
          ))}
        </section>
        <section className="connection panel">
          <div>
            <div className="eyebrow">SESSION CONTROLS</div>
            <h2>Connect the demonstration</h2>
            <p>
              {BROWSER_WALLET
                ? "Issuer: enter the admin token from the hosting environment. The wallet runs on this device. Keys and passphrases stay in this browser."
                : "Administrator: use the tokens from your private local .env file. Kept in page memory only."}
            </p>
          </div>
          <label>
            Issuer admin token
            <input
              type="password"
              value={admin}
              onChange={(e) => A(e.target.value)}
              autoComplete="off"
            />
          </label>
          {!BROWSER_WALLET && (
            <label>
              Holder wallet token
              <input
                type="password"
                value={holder}
                onChange={(e) => H(e.target.value)}
                autoComplete="off"
              />
            </label>
          )}
          {button("Connect / refresh", async () => {
            await refresh();
            RES("Issuer registry connected.");
          })}
        </section>
        <div className="grid">
          <section className="panel primary">
            <div className="eyebrow">
              {scenes[scenario][0].toUpperCase()} / LIVE WORKFLOW
            </div>
            {(tab === "Overview" || tab === "Registration") && (
              <>
                <h2>Issue a private credential</h2>
                <p>
                  The trusted issuer approves a demo identity.{" "}
                  {BROWSER_WALLET ? "This browser" : "The local holder wallet"}{" "}
                  creates a random credential and sends only its Poseidon
                  commitment.
                </p>
                <div className="fields">
                  <label>
                    Demo display name
                    <input
                      value={name}
                      maxLength={80}
                      onChange={(e) => N(e.target.value)}
                      placeholder="e.g. Alex Morgan"
                    />
                  </label>
                  <label>
                    Issuer-approved role
                    <select value={role} onChange={(e) => R(e.target.value)}>
                      {Object.values(scenes).map((v) => (
                        <option key={v[1]}>{v[1]}</option>
                      ))}
                    </select>
                  </label>
                </div>
                <label>
                  Wallet passphrase · at least 12 characters
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => P(e.target.value)}
                    autoComplete="new-password"
                  />
                </label>
                {button(
                  "Register & issue credential →",
                  issue,
                  !name || password.length < 12,
                )}
              </>
            )}
            {tab !== "Registration" && (
              <>
                <h2>
                  {tab === "Access Control"
                    ? "Authorize resource access"
                    : "Holder → verifier"}
                </h2>
                <label>
                  Registered identity
                  <select
                    value={uid}
                    onChange={(e) => selectUser(e.target.value)}
                  >
                    <option value="">Select an identity</option>
                    {state.users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.name} · {u.role}
                        {u.revoked ? " · REVOKED" : ""}
                      </option>
                    ))}
                  </select>
                </label>
                {tab !== "Overview" && (
                  <label>
                    Holder wallet passphrase
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => P(e.target.value)}
                    />
                  </label>
                )}
                <div className="actions">
                  {button(
                    "1. Generate proof",
                    generate,
                    !uid || password.length < 12,
                  )}
                  {button("2. Verify proof", verify, !proofText, "secondary")}
                  {button("3. Request access", open, false, "secondary")}
                </div>
                <p className="hint">
                  {scenes[scenario][2]} requires role{" "}
                  <b>{scenes[scenario][1]}</b> and an explicit issuer grant. You
                  can request access without a proof to demonstrate denial.
                </p>
              </>
            )}
            {tab === "Verification Portal" && (
              <label>
                Proof envelope · editable for tampering demonstrations
                <textarea
                  rows={14}
                  value={proofText}
                  onChange={(e) => PT(e.target.value)}
                  placeholder="Generate a proof in the holder wallet first"
                />
              </label>
            )}
            {BROWSER_WALLET && tab === "Credential Wallet" && (
              <div className="browser-backup">
                <p>
                  Wallet files live only in this browser. Back up before
                  clearing browser data or switching devices. Existing Python
                  wallet files use a different format.
                </p>
                {button(
                  "Download encrypted wallet backup",
                  async () => {
                    const blob = new Blob([walletBackup(uid)], {
                      type: "application/json",
                    });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = "veil-wallet-" + uid + ".json";
                    link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                    RES(
                      "Encrypted backup downloaded. Keep the passphrase separately.",
                    );
                  },
                  !uid,
                  "secondary",
                )}
                <label>
                  Import encrypted browser wallet backup
                  <input
                    type="file"
                    accept="application/json,.json"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      run(async () => {
                        if (file.size > 4096)
                          throw Error("Wallet backup is too large.");
                        const id = importWallet(await file.text());
                        selectUser(id);
                        RES("Encrypted wallet imported on this browser.");
                      });
                      e.target.value = "";
                    }}
                  />
                </label>
              </div>
            )}
            {tab === "Access Control" && (
              <div className="actions">
                {button(
                  "Grant permission",
                  async () => {
                    await request("/api/permission", {
                      uid,
                      scenario,
                      allowed: true,
                    });
                    await refresh();
                    RES("Permission granted.");
                  },
                  !uid,
                )}
                {button(
                  "Revoke permission",
                  async () => {
                    await request("/api/permission", {
                      uid,
                      scenario,
                      allowed: false,
                    });
                    await refresh();
                    RES(
                      "Permission revoked. Existing sessions lose access immediately.",
                    );
                  },
                  !uid,
                  "secondary",
                )}
                {button(
                  "Revoke credential",
                  async () => {
                    await request("/api/revoke", { uid });
                    await refresh();
                    RES("Credential revoked permanently.");
                  },
                  !uid,
                  "danger",
                )}
              </div>
            )}
          </section>
          <section className="panel">
            <div className="eyebrow">VERIFIER RESPONSE</div>
            <h2>{busy ? "Computing proof…" : "Evidence, then access."}</h2>
            <div
              className={
                "result " + (result.startsWith("Denied") ? "error" : "")
              }
              role="status"
              aria-live="polite"
            >
              <span>{busy ? "◌" : "◈"}</span>
              <p>
                {busy
                  ? "Processing real cryptographic operations. This may take a few seconds."
                  : result}
              </p>
            </div>
            <div className="security">
              <span>PRIVATE</span>
              <p>
                {BROWSER_WALLET
                  ? "Credential stays encrypted in this browser. The server receives only commitments and proofs."
                  : "Credential stays encrypted in the separate local wallet."}
              </p>
              <span>PUBLIC</span>
              <p>Commitment, challenge, session response and Groth16 proof.</p>
              <span>FRESH</span>
              <p>
                120-second challenge. One verification attempt. 180-second
                access session.
              </p>
            </div>
            {button(
              "Lock wallet / clear session",
              async () => {
                P("");
                A("");
                H("");
                AC("");
                PR(null);
                PT("");
                RES("Local page session cleared.");
              },
              false,
              "secondary",
            )}
          </section>
        </div>
        {(tab === "Audit Logs" || tab === "Overview") && (
          <section className="panel logs">
            <div className="eyebrow">ACCOUNTABILITY</div>
            <h2>
              Authentication trail{" "}
              <span className="badge">
                {state.integrity === undefined
                  ? "CONNECT TO CHECK"
                  : state.integrity
                    ? "HMAC CHAIN VALID"
                    : "INTEGRITY FAILED"}
              </span>
            </h2>
            <p>
              Latest 100 events. A keyed chain detects edits; external
              checkpoints are needed to detect suffix deletion or full rollback.
            </p>
            <table>
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>EVENT</th>
                  <th>SUBJECT</th>
                  <th>OUTCOME</th>
                </tr>
              </thead>
              <tbody>
                {state.events.map((e, i) => (
                  <tr key={i}>
                    <td>{new Date(e.time * 1000).toLocaleTimeString()}</td>
                    <td>{e.event.replaceAll("_", " ")}</td>
                    <td>{e.subject.slice(0, 12) || "—"}</td>
                    <td>
                      <code>{e.outcome}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!state.events.length && (
              <p>
                No events loaded. Connect the issuer to inspect the audit trail.
              </p>
            )}
          </section>
        )}
        <footer>
          VEIL / FINAL-YEAR RESEARCH PROTOTYPE
          <span>
            Credential privacy ≠ anonymous identity. Commitments remain
            linkable.
          </span>
        </footer>
      </main>
    </div>
  );
}
createRoot(document.getElementById("root")).render(<App />);
