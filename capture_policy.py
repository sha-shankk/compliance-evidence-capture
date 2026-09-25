#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright
from PIL import Image, ImageDraw, ImageFont

import evidence_common as ec

try:
    import requests
except ImportError:
    requests = None


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# 1. Capture: screenshot + PDF + HTML + metadata
# --------------------------------------------------------------------------- #
def capture_page(url: str, out_dir: Path, viewport=(1440, 900), timeout_ms=60000):
    user_agent = ("ComplianceCaptureBot/1.0 (+automation) "
                  "Chromium headless via Playwright")
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-dev-shm-usage"])
        context = browser.new_context(
            viewport={"width": viewport[0], "height": viewport[1]},
            user_agent=user_agent, locale="en-US")
        page = context.new_page()

        captured_at = utc_now_iso()
        response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        consent_dismissed = _try_dismiss_consent(page)
        page.wait_for_timeout(1500)

        # Screenshot (pristine, full page)
        screenshot_path = out_dir / "screenshot.png"
        page.screenshot(path=str(screenshot_path), full_page=True)

        # PDF rendition (headless Chromium). Screen media keeps it faithful to
        # what was captured rather than a print-styled variant.
        pdf_path = out_dir / "privacy-policy.pdf"
        page.emulate_media(media="screen")
        page.pdf(path=str(pdf_path), print_background=True, format="A4")

        # Rendered HTML
        html_path = out_dir / "page.html"
        html_path.write_text(page.content(), encoding="utf-8")

        # HTTP metadata
        interesting = ("last-modified", "etag", "content-type", "date", "server")
        resp_headers = {}
        if response is not None:
            resp_headers = {k: v for k, v in response.headers.items()
                            if k.lower() in interesting}
        response_meta = {
            "final_url": page.url,
            "http_status": response.status if response else None,
            "response_headers": resp_headers,
            "consent_banner_dismissed": consent_dismissed,
            "user_agent": user_agent,
            "viewport": {"width": viewport[0], "height": viewport[1]},
        }
        (out_dir / "response.json").write_text(
            json.dumps(response_meta, indent=2), encoding="utf-8")

        browser.close()

    return {
        "captured_at": captured_at,
        "screenshot": screenshot_path,
        "pdf": pdf_path,
        "html": html_path,
        "response": out_dir / "response.json",
        "response_meta": response_meta,
    }


def _try_dismiss_consent(page) -> bool:
    for selector in ("button:has-text('Accept all')",
                     "button:has-text('Accept All')",
                     "button:has-text('Accept')",
                     "button:has-text('I agree')",
                     "#onetrust-accept-btn-handler"):
        try:
            el = page.query_selector(selector)
            if el and el.is_visible():
                el.click(timeout=3000)
                page.wait_for_timeout(500)
                return True
        except Exception:
            continue
    return False


# --------------------------------------------------------------------------- #
# 2. Professional evidence banner (visible on the annotated screenshot)
# --------------------------------------------------------------------------- #
def make_annotated_screenshot(src_png: Path, dst_png: Path,
                              url: str, captured_at: str, run_id: str) -> None:
    """
    Append a labelled evidence banner ABOVE the original screenshot. The original
    pixels are untouched, so screenshot.png stays pristine for hashing while
    screenshot_annotated.png carries the human-readable, auditor-friendly banner.
    """
    original = Image.open(src_png).convert("RGB")
    fdir = "/usr/share/fonts/truetype/dejavu"
    try:
        f_head = ImageFont.truetype(f"{fdir}/DejaVuSans-Bold.ttf", 26)
        f_lab = ImageFont.truetype(f"{fdir}/DejaVuSans-Bold.ttf", 15)
        f_val = ImageFont.truetype(f"{fdir}/DejaVuSans.ttf", 17)
    except OSError:
        f_head = f_lab = f_val = ImageFont.load_default()

    pad = 22
    rows = [("URL:", url), ("Captured UTC:", captured_at), ("Run ID:", run_id)]
    head_h = 40
    row_h = 42
    banner_h = pad * 2 + head_h + row_h * len(rows)

    canvas = Image.new("RGB", (original.width, original.height + banner_h), "white")
    d = ImageDraw.Draw(canvas)
    d.rectangle([0, 0, canvas.width, banner_h], fill=(17, 24, 39))
    # accent bar
    d.rectangle([0, 0, 6, banner_h], fill=(29, 158, 117))

    d.text((pad, pad), "COMPLIANCE EVIDENCE CAPTURE", fill=(255, 255, 255), font=f_head)
    y = pad + head_h
    for label, value in rows:
        d.text((pad, y + 4), label, fill=(150, 200, 180), font=f_lab)
        d.text((pad + 160, y), value, fill=(240, 240, 240), font=f_val)
        y += row_h

    canvas.paste(original, (0, banner_h))
    canvas.save(dst_png)


# --------------------------------------------------------------------------- #
# 3. Manifest (PDF now included)
# --------------------------------------------------------------------------- #
def build_manifest(url: str, capture: dict, out_dir: Path, run_id: str) -> Path:
    files = {
        "screenshot.png": capture["screenshot"],
        "screenshot_annotated.png": out_dir / "screenshot_annotated.png",
        "privacy-policy.pdf": capture["pdf"],
        "page.html": capture["html"],
        "response.json": capture["response"],
    }
    file_hashes = {name: {"sha256": ec.sha256_file(path),
                          "bytes": path.stat().st_size}
                   for name, path in files.items()}
    manifest = {
        "schema": "compliance-capture/1.1",
        "run_id": run_id,
        "target_url": url,
        "captured_at_utc": capture["captured_at"],
        "capture": capture["response_meta"],
        "hash_algorithm": "SHA-256",
        "files": file_hashes,
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


# --------------------------------------------------------------------------- #
# 4. RFC 3161 trusted timestamp (quieted; full output in --verbose)
# --------------------------------------------------------------------------- #
def timestamp_manifest(manifest_path: Path, tsa_url: str, out_dir: Path,
                       verbose: bool) -> dict:
    if requests is None:
        raise RuntimeError("The 'requests' package is required for timestamping.")
    tsq = out_dir / "manifest.tsq"
    tsr = out_dir / "manifest.tsr"
    subprocess.run(
        ["openssl", "ts", "-query", "-data", str(manifest_path),
         "-sha256", "-cert", "-out", str(tsq)],
        check=True,
        stdout=None if verbose else subprocess.DEVNULL,
        stderr=None if verbose else subprocess.DEVNULL)
    resp = requests.post(tsa_url, data=tsq.read_bytes(),
                         headers={"Content-Type": "application/timestamp-query"},
                         timeout=30)
    resp.raise_for_status()
    tsr.write_bytes(resp.content)
    return {"tsa_url": tsa_url, "response_file": tsr.name,
            "manifest_sha256": ec.sha256_file(manifest_path)}


# --------------------------------------------------------------------------- #
# One capture run for a single URL
# --------------------------------------------------------------------------- #
def run_capture(url: str, bundle_dir: Path, run_id: str, args) -> dict:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Capturing {url}")
    capture = capture_page(url, bundle_dir)
    print(f"    captured_at (UTC): {capture['captured_at']}")

    make_annotated_screenshot(
        capture["screenshot"], bundle_dir / "screenshot_annotated.png",
        url=url, captured_at=capture["captured_at"], run_id=run_id)

    manifest_path = build_manifest(url, capture, bundle_dir, run_id)
    manifest_sha = ec.sha256_file(manifest_path)
    print(f"    manifest SHA-256: {manifest_sha}")

    timestamp_result = None
    if args.tsa_provider:
        tsa_url = ec.TSA_PROVIDERS[args.tsa_provider]["url"]
        try:
            timestamp_result = timestamp_manifest(
                manifest_path, tsa_url, bundle_dir, args.verbose)
            print(f"[*] Trusted timestamp obtained from {tsa_url}")
        except Exception as exc:
            print(f"[!] Trusted timestamp step failed: {exc}", file=sys.stderr)

    verification = None
    if not args.no_self_verify:
        print("[*] Verifying evidence:")
        verification = ec.run_verification(bundle_dir, args.tsa_provider, args.cert_dir)
        ec.print_verification(verification, verbose=args.verbose, indent="    ")

    # Human-readable report (derived view, not a trust anchor)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_meta = {
        "run_id": run_id, "target_url": url,
        "captured_at": capture["captured_at"],
        "tsa_provider": args.tsa_provider,
        "manifest_sha256": manifest_sha,
    }
    verif_for_report = verification or ec.run_verification(
        bundle_dir, args.tsa_provider, args.cert_dir)
    ec.write_report_html(bundle_dir, manifest, verif_for_report, report_meta)

    receipt = {
        "run_id": run_id, "target_url": url,
        "captured_at_utc": capture["captured_at"],
        "manifest_sha256": manifest_sha,
        "trusted_timestamp": timestamp_result,
        "verification": verification,
        "report": "report.html",
        "files": sorted(p.name for p in bundle_dir.iterdir()),
    }
    (bundle_dir / "receipt.json").write_text(
        json.dumps(receipt, indent=2), encoding="utf-8")

    ok = verification["overall"] if verification else True
    return {"url": url, "bundle": bundle_dir, "overall": ok}


# --------------------------------------------------------------------------- #
# main (single URL or urls.txt)
# --------------------------------------------------------------------------- #
def load_urls(args) -> list[str]:
    if args.urls_file:
        lines = Path(args.urls_file).read_text(encoding="utf-8").splitlines()
        urls = [ln.strip() for ln in lines
                if ln.strip() and not ln.strip().startswith("#")]
        if not urls:
            raise SystemExit(f"No URLs found in {args.urls_file}")
        return urls
    return [args.url]


def main() -> int:
    ap = argparse.ArgumentParser(description="Compliance-grade page capture.")
    ap.add_argument("--url",
                    default="https://www.mindtickle.com/legal/privacy-policy/")
    ap.add_argument("--urls-file",
                    help="Path to urls.txt (one URL per line). Overrides --url.")
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--tsa-provider", default="freetsa",
                    help="TSA operator key, or '' to skip trusted timestamping.")
    ap.add_argument("--cert-dir", default="certs")
    ap.add_argument("--no-self-verify", action="store_true")
    ap.add_argument("--verbose", action="store_true",
                    help="Show full openssl output and TSA warnings.")
    args = ap.parse_args()

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    urls = load_urls(args)
    multi = len(urls) > 1
    run_root = Path(args.out) / run_id

    results = []
    for url in urls:
        bundle_dir = run_root / ec.slugify_url(url) if multi else run_root
        try:
            results.append(run_capture(url, bundle_dir, run_id, args))
        except Exception as exc:
            print(f"[!] Capture failed for {url}: {exc}", file=sys.stderr)
            results.append({"url": url, "bundle": bundle_dir, "overall": False})
        print()

    print("=" * 56)
    if multi:
        for r in results:
            tag = "VERIFIED" if r["overall"] else "FAILED"
            print(f"  [{tag}] {r['url']}")
    print(f"[+] Evidence written under: {run_root.resolve()}")

    return 0 if all(r["overall"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
