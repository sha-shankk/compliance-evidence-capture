#!/usr/bin/env python3
"""
Independently verify a captured evidence bundle (or a multi-URL run folder).

Zero manual setup: the TSA certificates are auto-fetched (CA pinned by SHA-256)
the same way the capture pipeline does. Clean [PASS]/[FAIL] output; --verbose
shows the full openssl detail.

Usage:
    python verify_evidence.py evidence/<run_id>
    python verify_evidence.py evidence/<run_id> --verbose
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import evidence_common as ec


def _bundles_under(path: Path) -> list[Path]:
    """A path is a bundle if it has manifest.json; otherwise treat its immediate
    subfolders (a multi-URL run) as bundles."""
    if (path / "manifest.json").exists():
        return [path]
    subs = sorted(p for p in path.iterdir()
                  if p.is_dir() and (p / "manifest.json").exists())
    return subs


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a compliance evidence bundle.")
    ap.add_argument("bundle", help="An evidence/<run_id> folder (single or multi-URL).")
    ap.add_argument("--tsa-provider", default="freetsa",
                    help="TSA operator whose certs to use. '' to skip time check.")
    ap.add_argument("--cert-dir", default="certs")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = Path(args.bundle)
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 2

    bundles = _bundles_under(root)
    if not bundles:
        print(f"No manifest.json found in {root} or its subfolders", file=sys.stderr)
        return 2

    all_ok = True
    for b in bundles:
        if len(bundles) > 1:
            print(f"\n=== {b.name} ===")
        result = ec.run_verification(b, args.tsa_provider, args.cert_dir)
        ec.print_verification(result, verbose=args.verbose, indent="")
        all_ok = all_ok and result["overall"]

    print("\n" + "=" * 50)
    print(f"RESULT: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
