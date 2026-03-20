# FirmwareLens Firmware Security Analyzer

FirmwareLens is a firmware analysis web app that scans uploaded firmware, generates a full report, stores scan history by `scan_id`, and gives users a built-in support center for Sentinel Bot chat, feedback, and field issue reporting when no debugger is available.

## What It Does

- User registration and login for the Flask UI
- Firmware upload and full free scan
- Detection of hardcoded secrets, weak crypto, suspicious strings, outdated libraries, and bad practices
- HTML and PDF report generation
- Bot-guided triage through Sentinel Bot
- Feedback collection from users
- Field issue reporting with bot-generated solution suggestions
- JSON scan retrieval through FastAPI

## Main Features

### Analyzer

- Upload `.bin`, `.img`, `.fw`, `.hex`, or `.elf`
- Get the full findings list for free
- Download a free PDF report
- Review business-risk and remediation-oriented summaries

### Sentinel Bot Support

- Ask scan-specific or general troubleshooting questions
- Receive guided next steps for secrets, crypto, crashes, OTA, networking, and memory-related problems
- Persist recent bot conversations per user

### Field Issue Reports

- Capture symptoms seen in the field when a debugger is unavailable
- Store device model, firmware version, environment details, and user-entered symptoms
- Generate a structured bot solution with probable causes and next field actions

### Feedback

- Collect ratings and category-based product feedback
- Persist feedback for future review and product improvement

## Key Files

- [app.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/app.py): Flask app, FirmwareLens login flow, support routes
- [main.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/main.py): ASGI shim for platforms using `uvicorn main:app`
- [api/main.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/api/main.py): FastAPI endpoints
- [engine/analyzer.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/engine/analyzer.py): core scan pipeline
- [engine/ai_agent.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/engine/ai_agent.py): report bot summary builder
- [engine/bot_support.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/engine/bot_support.py): support chat and field issue solution logic
- [services/app_db.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/services/app_db.py): SQLite-backed users, feedback, field reports, bot chat
- [services/scan_store.py](/C:/Users/Himan/Downloads/firmware-security-analyzer/services/scan_store.py): scan-specific upload, result, and report storage
- [templates/index.html](/C:/Users/Himan/Downloads/firmware-security-analyzer/templates/index.html): home page with inline auth and upload workflow
- [templates/result.html](/C:/Users/Himan/Downloads/firmware-security-analyzer/templates/result.html): report page
- [templates/support.html](/C:/Users/Himan/Downloads/firmware-security-analyzer/templates/support.html): support center

## Running The App

### Install Dependencies

```sh
pip install -r requirements.txt
```

### Flask UI

```powershell
python app.py
```

Then open:

- `http://127.0.0.1:5000/`

The home page now includes:

- account login
- account registration
- guest access
- the firmware upload workspace after sign-in

If a platform expects an ASGI entrypoint, you can also serve the same Flask UI with:

```powershell
uvicorn main:app --host 0.0.0.0 --port 5000
```

### FastAPI

```powershell
uvicorn api.main:app --reload
```

Useful endpoints:

- `GET /health`
- `POST /upload`
- `POST /analyze`
- `GET /analyze-json/{scan_id}`
- `GET /download-report?scan_id=...`

## Running Tests

```sh
pytest
```

Individual test files:

```sh
pytest tests/test_analyzer.py
pytest tests/test_revenue_model.py
pytest tests/test_secret_detector.py
pytest tests/test_scan_store.py
pytest tests/test_bot_support.py
pytest tests/test_app_db.py
pytest tests/test_config.py
```

## Deployment And Global Launch

FirmwareLens now includes production launch files:

- [Procfile](/C:/Users/Himan/Downloads/firmware-security-analyzer/Procfile)
- [render.yaml](/C:/Users/Himan/Downloads/firmware-security-analyzer/render.yaml)
- [.env.example](/C:/Users/Himan/Downloads/firmware-security-analyzer/.env.example)
- [DEPLOYMENT.md](/C:/Users/Himan/Downloads/firmware-security-analyzer/DEPLOYMENT.md)

Key deployment notes:

- `RUNTIME_ROOT` lets you move uploads, reports, scan results, and SQLite onto persistent storage.
- `/robots.txt` and `/sitemap.xml` are now built in for discovery.
- `/ads.txt` is available when `ADS_TXT_CONTENT` is configured.
- CSP now allows GA4 correctly when `GA_MEASUREMENT_ID` is set.
- Vercel now falls back to `/tmp/firmwarelens` so the app can boot in serverless preview mode, but full production scans still belong on a persistent host like Render.

## Analytics And Global Popularity Tracking

FirmwareLens can emit GA4-ready UI events when `GA_MEASUREMENT_ID` is set in the environment.

Main tracked events include:

- `sign_up`
- `guest_login`
- `scan_started`
- `scan_completed`
- `report_downloaded`
- `support_opened`
- `bot_chat_used`
- `field_issue_reported`

For the full analytics plan and global traction dashboard, see [ANALYTICS_SETUP.md](/C:/Users/Himan/Downloads/firmware-security-analyzer/ANALYTICS_SETUP.md).

## Runtime Directories

- `data/`: SQLite database
- `uploads/`: uploaded firmware binaries
- `extracted/`: extracted firmware contents
- `scan_results/`: persisted JSON scan results
- `reports/`: generated PDF reports

## Notes

- Demo secret injection was removed from the analyzer.
- Revenue values are modeled estimates, not audited financial forecasts.
- Reports are keyed by `scan_id`, not shared global state.
- Flask authentication is now backed by stored users with hashed passwords.
- For stronger production security, set `FLASK_SECRET_KEY`, `COOKIE_SECURE=1`, and `SITE_URL` in the environment instead of relying on the development fallback values.
- On Vercel, local storage is temporary and upload limits are smaller, so that deployment mode should be treated as a preview rather than the full production workflow.
