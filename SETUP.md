# Running this project from scratch (VS Code)

## 0. Install prerequisites (once)

- **Python 3.10+** (3.12 recommended). Windows: download from python.org and
  **tick "Add Python to PATH"** in the installer.
- **VS Code** + the **Python** extension (by Microsoft).
- **OpenSSL** (needed for the trusted-timestamp step):
  - macOS: already present (or `brew install openssl`).
  - Linux: already present (or `sudo apt install openssl`).
  - Windows: `winget install ShiningLight.OpenSSL.Light`, or run the commands
    from **Git Bash** (Git for Windows ships openssl). Verify with `openssl version`.

## 1. Get the project

Download and extract the project zip so you have a folder like
`compliance-capture/` containing `capture_policy.py`, `verify_evidence.py`,
`evidence_common.py`, `requirements.txt`, etc.

## 2. Open it in VS Code

`File > Open Folder…` and pick the `compliance-capture` folder.
Then open the integrated terminal: `Terminal > New Terminal` (or Ctrl+`).

## 3. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
If activation is blocked, run once:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and retry,
or use `\.venv\Scripts\activate.bat` in a Command Prompt terminal.

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then press `Ctrl+Shift+P` → "Python: Select Interpreter" → choose the `.venv` one.

## 4. Install dependencies

```bash
pip install -r requirements.txt
python -m playwright install chromium
```
(The second command downloads the headless browser — first time only.)

## 5. Run the capture

```bash
python capture_policy.py --url "https://www.mindtickle.com/legal/privacy-policy/" --tsa-provider freetsa
```
It prints the capture time, the manifest hash, and ends with the
self-verification result. Output lands in `evidence/<UTC-timestamp>/`.

Open that folder and look at:
- `screenshot_annotated.png` — visible timestamp banner
- `manifest.json` — the SHA-256 hashes
- `receipt.json` — one-glance summary incl. self-verification

## 6. Verify independently

```bash
python verify_evidence.py evidence/<run_id>
```
Ends with `RESULT: PASS`.

## 7. The tamper demo (show this in the interview)

1. Open `evidence/<run_id>/page.html` and change one character, save.
2. Run `python verify_evidence.py evidence/<run_id>` again.
3. It now prints `FAIL` on `page.html` and `RESULT: FAIL` — tamper detected.
4. Undo your edit to make it PASS again.

## Notes / troubleshooting

- No internet or don't want the TSA? Run with `--tsa-provider ""` — you still get
  the screenshot + hashes (integrity), just no independent trusted time.
- `openssl: command not found` (Windows) → install it (step 0) or use Git Bash.
- Corporate proxy blocking the browser download → set `HTTPS_PROXY` env var, or
  run `python -m playwright install chromium` on a normal network once.
