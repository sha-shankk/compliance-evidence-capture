#!/usr/bin/env python3
"""
Shared helpers for capture, verification, and reporting.

Kept in one module so the capture pipeline self-verifies with the exact same
code path an auditor uses later, and neither side needs a manual step.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None


# TSA operators. The CA certificate is the trust anchor and is *pinned* by
# SHA-256 so it can't be silently swapped. The signer cert (tsa.crt) may rotate,
# so it's fetched fresh and only used as the `-untrusted` intermediate.
TSA_PROVIDERS = {
    "freetsa": {
        "url": "https://freetsa.org/tsr",
        "cacert_url": "https://freetsa.org/files/cacert.pem",
        "tsa_cert_url": "https://freetsa.org/files/tsa.crt",
        "cacert_sha256":
            "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438",
    },
}

# Friendly labels for the clean verification UX.
FRIENDLY_LABELS = {
    "screenshot.png": "Screenshot integrity",
    "screenshot_annotated.png": "Annotated screenshot integrity",
    "privacy-policy.pdf": "PDF integrity",
    "page.html": "HTML integrity",
    "response.json": "Metadata integrity",
}
# Order in which artifact checks are displayed.
DISPLAY_ORDER = ["screenshot.png", "privacy-policy.pdf", "page.html",
                 "response.json", "screenshot_annotated.png"]


def friendly_label(name: str) -> str:
    return FRIENDLY_LABELS.get(name, f"{name} integrity")


def slugify_url(url: str) -> str:
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")
    return slug or "site"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    if requests is None:
        raise RuntimeError("The 'requests' package is required to fetch certs.")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    dest.write_bytes(resp.content)


def ensure_tsa_certs(provider: str, cert_dir: Path) -> tuple[Path, Path]:
    """Download + cache the TSA certs if absent; verify the CA against its pin."""
    if provider not in TSA_PROVIDERS:
        raise ValueError(f"Unknown TSA provider: {provider}")
    cfg = TSA_PROVIDERS[provider]
    cert_dir = Path(cert_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_path = cert_dir / f"{provider}_cacert.pem"
    tsa_path = cert_dir / f"{provider}_tsa.crt"
    if not ca_path.exists():
        _download(cfg["cacert_url"], ca_path)
    got = sha256_file(ca_path)
    if got != cfg["cacert_sha256"]:
        raise RuntimeError(
            f"CA cert pin mismatch for '{provider}'. "
            f"expected {cfg['cacert_sha256']}, got {got}")
    if not tsa_path.exists():
        _download(cfg["tsa_cert_url"], tsa_path)
    return ca_path, tsa_path


def verify_integrity(bundle: Path) -> tuple[bool, list[dict]]:
    """Recompute SHA-256 of every file in the manifest and compare."""
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    results, ok = [], True
    names = list(manifest["files"].keys())
    ordered = [n for n in DISPLAY_ORDER if n in names] + \
              [n for n in names if n not in DISPLAY_ORDER]
    for name in ordered:
        meta = manifest["files"][name]
        target = bundle / name
        present = target.exists()
        match = present and sha256_file(target) == meta["sha256"]
        ok = ok and match
        results.append({"name": name, "ok": match, "present": present})
    return ok, results


def verify_timestamp(bundle: Path, ca_cert: Path, tsa_cert: Path) -> tuple[bool, str]:
    """Verify the RFC 3161 token against the manifest using openssl."""
    tsr = bundle / "manifest.tsr"
    manifest = bundle / "manifest.json"
    if not tsr.exists():
        return True, "SKIPPED (no manifest.tsr in bundle)"
    try:
        result = subprocess.run(
            ["openssl", "ts", "-verify", "-data", str(manifest),
             "-in", str(tsr), "-CAfile", str(ca_cert), "-untrusted", str(tsa_cert)],
            capture_output=True, text=True)
    except FileNotFoundError:
        return False, "openssl not found on PATH"
    output = (result.stdout + result.stderr).strip()
    passed = result.returncode == 0 and "Verification: OK" in output
    return passed, output


def run_verification(bundle: Path, tsa_provider: str = "freetsa",
                     cert_dir: str = "certs") -> dict:
    """Full verification of a bundle, returned as a structured result."""
    bundle = Path(bundle)
    integ_ok, files = verify_integrity(bundle)
    result = {"files": files, "integrity_ok": integ_ok,
              "timestamp_ok": None, "manifest_ok": None, "timestamp_detail": ""}
    tsr = bundle / "manifest.tsr"
    if tsa_provider and tsr.exists():
        try:
            ca, tsa = ensure_tsa_certs(tsa_provider, Path(cert_dir))
            ts_ok, out = verify_timestamp(bundle, ca, tsa)
            result["timestamp_ok"] = ts_ok
            result["manifest_ok"] = ts_ok  # openssl proves manifest hash unchanged
            result["timestamp_detail"] = out
        except Exception as exc:
            result["timestamp_ok"] = False
            result["manifest_ok"] = False
            result["timestamp_detail"] = str(exc)
    result["overall"] = integ_ok and (result["timestamp_ok"] is not False)
    return result


def print_verification(result: dict, verbose: bool = False, indent: str = "") -> None:
    for f in result["files"]:
        tag = "PASS" if f["ok"] else "FAIL"
        print(f"{indent}[{tag}] {friendly_label(f['name'])}")
    if result["manifest_ok"] is not None:
        print(f"{indent}[{'PASS' if result['manifest_ok'] else 'FAIL'}] Manifest integrity")
        print(f"{indent}[{'PASS' if result['timestamp_ok'] else 'FAIL'}] Trusted timestamp verification")
    else:
        print(f"{indent}[SKIP] Trusted timestamp verification (no token in bundle)")
    print(f"{indent}Overall Result: {'VERIFIED' if result['overall'] else 'FAILED'}")
    if verbose and result["timestamp_detail"]:
        print(f"{indent}  openssl: {result['timestamp_detail']}")


def _pill(ok, skipped=False) -> str:
    if skipped:
        return '<span class="pill skip">SKIPPED</span>'
    return ('<span class="pill pass">PASS</span>' if ok
            else '<span class="pill fail">FAIL</span>')


def write_report_html(bundle: Path, manifest: dict, result: dict, meta: dict) -> Path:
    """Auditor-friendly HTML report derived from verified evidence.

    This report is a *human-readable view*, not a trust anchor: the manifest and
    the RFC 3161 token remain the authoritative evidence.
    """
    bundle = Path(bundle)
    rows = []
    names = list(manifest["files"].keys())
    ordered = [n for n in DISPLAY_ORDER if n in names] + \
              [n for n in names if n not in DISPLAY_ORDER]
    for name in ordered:
        h = manifest["files"][name]["sha256"]
        size = manifest["files"][name].get("bytes", "")
        rows.append(f"<tr><td>{html.escape(name)}</td>"
                    f"<td class='mono'>{h}</td><td class='num'>{size}</td></tr>")
    artifact_rows = "\n".join(rows)

    ts_skipped = result["timestamp_ok"] is None
    overall = "EVIDENCE VERIFIED" if result["overall"] else "VERIFICATION FAILED"
    overall_pill = _pill(result["overall"])
    ts_iso = meta.get("captured_at", "")
    tsa = meta.get("tsa_provider") or "none (local hashes only)"

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance Evidence Report - {html.escape(meta.get('run_id',''))}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         color:#1f2430; max-width:860px; margin:24px auto; padding:0 18px; line-height:1.5; }}
  h1 {{ font-size:22px; margin:0 0 2px; }}
  .sub {{ color:#5f5e5a; font-size:13px; margin-bottom:18px; }}
  .banner {{ background:#111827; color:#fff; padding:14px 18px; border-radius:10px; margin-bottom:18px; }}
  .banner .big {{ font-size:20px; font-weight:600; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; margin:6px 0 18px; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #ececec; vertical-align:top; }}
  th {{ color:#5f5e5a; font-weight:600; }}
  .mono {{ font-family:ui-monospace, Consolas, monospace; font-size:11.5px; word-break:break-all; color:#374151; }}
  .num {{ color:#8a8a86; white-space:nowrap; }}
  .kv td:first-child {{ color:#5f5e5a; width:190px; }}
  .pill {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; }}
  .pass {{ background:#e1f5ee; color:#0f6e56; }}
  .fail {{ background:#fceaea; color:#a32d2d; }}
  .skip {{ background:#f1efe8; color:#5f5e5a; }}
  .result {{ font-size:18px; font-weight:600; margin:6px 0 20px; }}
  .note {{ background:#faf7ef; border:1px solid #eadfbf; border-radius:8px; padding:10px 14px; font-size:12.5px; color:#6b5d33; }}
  h2 {{ font-size:15px; margin:20px 0 6px; color:#0f6e56; }}
</style></head><body>
<div class="banner">
  <div class="big">COMPLIANCE EVIDENCE REPORT</div>
  <div>{html.escape(meta.get('target_url',''))}</div>
</div>

<table class="kv">
  <tr><td>Target URL</td><td>{html.escape(meta.get('target_url',''))}</td></tr>
  <tr><td>Run ID</td><td class="mono">{html.escape(meta.get('run_id',''))}</td></tr>
  <tr><td>Capture time (UTC)</td><td>{html.escape(ts_iso)}</td></tr>
  <tr><td>Timestamp authority</td><td>{html.escape(str(tsa))}</td></tr>
  <tr><td>Manifest SHA-256</td><td class="mono">{html.escape(meta.get('manifest_sha256',''))}</td></tr>
</table>

<h2>Artifacts captured</h2>
<table>
  <tr><th>File</th><th>SHA-256</th><th>Bytes</th></tr>
  {artifact_rows}
</table>

<h2>Verification results</h2>
<table>
  <tr><td>Content integrity (all artifacts)</td><td>{_pill(result['integrity_ok'])}</td></tr>
  <tr><td>Manifest integrity</td><td>{_pill(result['manifest_ok'], ts_skipped)}</td></tr>
  <tr><td>RFC 3161 trusted timestamp</td><td>{_pill(result['timestamp_ok'], ts_skipped)}</td></tr>
</table>

<div class="result">Overall result: {overall_pill} &nbsp; {html.escape(overall)}</div>

<div class="note">This report is a human-readable summary generated from the verified
evidence. It is <b>not</b> the trust anchor &mdash; authenticity rests on
<code>manifest.json</code> (SHA-256 chain of custody) and the RFC 3161 timestamp
token (<code>manifest.tsr</code>), both of which can be re-verified independently
with <code>verify_evidence.py</code> and standard <code>openssl</code> tooling.</div>
</body></html>"""
    report_path = bundle / "report.html"
    report_path.write_text(doc, encoding="utf-8")
    return report_path
