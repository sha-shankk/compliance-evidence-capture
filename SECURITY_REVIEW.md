# Security & Compliance Review

Scope: the compliance-evidence capture pipeline (Playwright capture → SHA-256
manifest → RFC 3161 trusted timestamp → self-verification → report). This review
preserves the existing trust model and assesses it honestly, the way an auditor
or a security interviewer would.

---

## 1. What the system proves — and what it does not

**It proves:** that *this specific set of bytes* (screenshot, PDF, HTML, metadata)
existed in this exact form **no later than** the UTC time attested by an
independent RFC 3161 authority, and that none of it has changed since. This is
integrity + trusted time + tamper-evidence.

**It does not prove, on its own:**
- *Who* performed the capture (operator/source non-repudiation).
- That the captured content is what the site served to **the public** — only what
  **our browser rendered** on our host at capture time.
- A legally *qualified* timestamp (FreeTSA is a standard, not a qualified/eIDAS TSA).

Stating these boundaries plainly is itself a strength in an audit: the system
does not over-claim.

---

## 2. Trust assumptions (explicit)

1. The capture host, OS, browser build, and network path are not compromised at
   capture time.
2. TLS to the target is validated (Playwright verifies certificates by default),
   so the content came from the real origin over an authenticated channel.
3. The pinned FreeTSA **CA certificate** (SHA-256 pinned) is authentic; the TSA
   signs honestly and keeps accurate time.
4. SHA-256 remains collision-resistant.
5. Evidence at rest is stored somewhere that is not silently mutable (ideally
   WORM / object-lock).

---

## 3. Risk register

Each risk: **likelihood**, **impact**, **mitigation** (and whether already in place).

### R1 — Compromised capture host injects false content
- **Risk:** malware, a rogue local CA, or a poisoned proxy makes the browser
  render content the origin never served; the pipeline faithfully timestamps it.
- **Likelihood:** Low (controlled runner) / Medium (an analyst's laptop).
- **Impact:** High — undermines authenticity of the content itself.
- **Mitigation:** run on a hardened, ephemeral CI runner; record the TLS
  certificate chain in `response.json`; optionally capture from ≥2 independent
  network vantage points and compare hashes. *(Partly in place; TLS-chain
  recording is a recommended enhancement — see §5.)*

### R2 — No proof of *who* captured (non-repudiation of source)
- **Risk:** the token proves time + integrity but not operator/org identity.
- **Likelihood:** N/A (design gap).
- **Impact:** Medium — an auditor may ask "who produced this?"
- **Mitigation:** sign `manifest.json` with an organisation key (X.509 / Sigstore
  cosign / GPG) **in addition to** the TSA. *(Recommended — see §5.)*

### R3 — Single TSA dependency (trust + availability)
- **Risk:** FreeTSA is one point of trust and one point of failure.
- **Likelihood:** Medium (availability) / Low (trust).
- **Impact:** Medium.
- **Mitigation:** provider is already configurable (DigiCert etc.); add a second
  independent anchor via **OpenTimestamps** (blockchain) and/or a **qualified TSA**
  for regulated use. Retain the TSA cert chain so tokens verify offline even if
  the TSA disappears.

### R4 — CA-pin maintenance
- **Risk:** if FreeTSA rotates its **CA**, the pinned hash must be updated or
  verification breaks.
- **Likelihood:** Low (CAs are long-lived; the *signer* cert rotating is handled
  automatically).
- **Impact:** Low/Medium (verification outage, not a security breach).
- **Mitigation:** documented, change-controlled pin update; alert on pin
  mismatch (already fails closed rather than trusting a swapped anchor).

### R5 — Long-term verifiability (cert/algorithm expiry)
- **Risk:** TSA signer certs expire and SHA-256 will eventually weaken; a token
  kept for many years may become hard to verify.
- **Likelihood:** Low near-term, certain long-term.
- **Impact:** Medium for long-retention compliance.
- **Mitigation:** retain the full cert chain with each bundle; for multi-year
  retention, add **archive timestamps / Evidence Record Syntax (RFC 4998)** —
  re-timestamp before algorithm or cert obsolescence. Manifest records the hash
  algorithm to enable migration (hash agility).

### R6 — Supply-chain / CVEs (Playwright, Chromium, OpenSSL, requests)
- **Risk:** a dependency vulnerability affects capture or verification.
- **Likelihood:** Medium (OpenSSL has had frequent 2026 advisories).
- **Impact:** Low→Medium (our use is local `openssl ts`, not network-facing TLS
  server code, so most CVEs don't apply).
- **Mitigation:** pin dependency versions; patch regularly; the pinned-CA design
  limits blast radius of a bad cert.

### R7 — Report/receipt mistaken for the trust anchor
- **Risk:** an auditor treats `report.html` / `receipt.json` as the evidence.
- **Likelihood:** Medium.
- **Impact:** Low.
- **Mitigation:** the report **states in-document** that it is a derived view and
  that authority rests on `manifest.json` + `manifest.tsr`. *(In place.)*

### R8 — Storage tampering / wholesale replacement
- **Risk:** someone with write access deletes a bundle or swaps in a new,
  internally-consistent one.
- **Likelihood:** Low (with controls).
- **Impact:** Medium.
- **Mitigation:** WORM / object-lock storage, append-only audit log, off-site
  copy. Note: an attacker cannot forge an **earlier** time — re-capturing yields a
  later TSA time, so back-dating is already prevented.

---

## 4. Likely audit objections → responses

| Objection | Response |
|-----------|----------|
| "How do we know the time wasn't faked?" | Independent RFC 3161 token, signer chains to a **pinned** CA; our own clock is used only for display, never as the authority. |
| "How do we know the file wasn't edited later?" | SHA-256 per file → manifest → timestamped manifest hash. Re-run `verify_evidence.py`; any change prints FAIL. |
| "How do we know it's the real site?" | TLS is validated at capture; the cert chain is recorded. (Caveat: host trust — see R1.) |
| "Who captured this?" | Currently the CI/pipeline identity; recommended: org-key signature on the manifest (R2). |
| "What if FreeTSA disappears?" | The token + retained certs verify offline forever; add a second anchor (R3). |
| "Is a free TSA acceptable?" | RFC 3161 is the industry standard; swap in a **qualified** TSA for eIDAS-grade needs — one config change. |

---

## 5. Recommended enhancements (prioritised)

**Now / low-effort, high-credibility**
- Record the **TLS certificate chain** of the target in `response.json` (addresses R1).
- **Sign `manifest.json` with an org key** (cosign/GPG) for source non-repudiation (R2).

**Next**
- **OpenTimestamps** second anchor for independent, operator-free time corroboration (R3).
- **WORM/object-lock** storage target + append-only run log (R8).

**Later / for regulated use**
- **Qualified (eIDAS) TSA** option; **RFC 4998 archive timestamps** for long retention (R5).
- Multi-vantage capture and hash comparison (R1).

---

## 6. Compliance notes (not legal advice)

- **Chain of custody:** the manifest + timestamp + verification logs + immutable
  storage give a defensible acquisition-to-verification trail.
- **Digital-evidence handling principles** (e.g. ISO/IEC 27037-style: identify,
  acquire, preserve, document): the pipeline documents acquisition, preserves via
  hashing/timestamping, and makes verification reproducible.
- **eIDAS:** the design is timestamp-authority-agnostic, so a qualified trust
  service can be substituted where a qualified electronic timestamp is required.

I am not a lawyer; the above maps the technical controls to common evidentiary
expectations rather than certifying legal sufficiency.
