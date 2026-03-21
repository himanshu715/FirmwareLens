# FirmwareLens Deployment Guide

This project can be launched quickly on Render, then placed behind Cloudflare for global delivery and DNS control.

## Quick Note On Vercel

FirmwareLens can now boot on Vercel in a lightweight preview mode by using `/tmp/firmwarelens` automatically when `VERCEL` is present, but Vercel serverless is still not the best production fit for this app because:

- storage is temporary
- uploads are more constrained
- scan history and generated reports are less reliable across invocations

Use Render or another persistent host for the full product workflow.

## 1. Prepare The Repo

- Keep [requirements.txt](/C:/Users/Himan/Downloads/firmware-security-analyzer/requirements.txt) up to date.
- Use [Procfile](/C:/Users/Himan/Downloads/firmware-security-analyzer/Procfile) or [render.yaml](/C:/Users/Himan/Downloads/firmware-security-analyzer/render.yaml) for the web start command.
- Copy [.env.example](/C:/Users/Himan/Downloads/firmware-security-analyzer/.env.example) to your local environment and set real secrets before deploying.

## 2. Recommended Render Setup

The included [render.yaml](/C:/Users/Himan/Downloads/firmware-security-analyzer/render.yaml) assumes:

- `gunicorn app:app` for production serving
- `uvicorn main:app --host 0.0.0.0 --port $PORT` as a compatibility fallback if your platform is preconfigured for ASGI
- `/health` as the health check path
- a persistent disk mounted at `/var/data`
- `RUNTIME_ROOT=/var/data/firmwarelens` so uploads, reports, scan results, and the SQLite database live on persistent storage

Important environment values:

- `FLASK_SECRET_KEY`: set to a strong random value
- `COOKIE_SECURE=1`: required for HTTPS deployments
- `SITE_URL=https://your-domain.example`: used for canonical URLs, sitemap generation, and robots output
- `FRONTEND_PUBLIC_URL=https://firmware-lens.vercel.app`: lets the backend allow browser API calls from the Vercel frontend
- `GA_MEASUREMENT_ID`: optional, enables GA4 tracking
- `ADS_TXT_CONTENT`: optional, publishes `/ads.txt` when you are ready for ad networks
- `API_ACCESS_KEY`: optional, protects the FastAPI upload/analyze endpoints

## 3. Optional Vercel Frontend -> Render Backend Split

If you keep the marketing/frontend deployment on Vercel and the scan runtime on Render:

- Set `BACKEND_PUBLIC_URL=https://firmwarelens.onrender.com` on the Vercel project.
- Optionally set `PUBLIC_SCAN_MAX_UPLOAD_SIZE_BYTES` on Vercel to match the Render upload limit if you override the backend default.
- The Vercel home page will then post firmware directly to `https://firmwarelens.onrender.com/public/analyze` instead of the Vercel runtime.
- The Flask backend on Render now also exposes `POST /upload`, `POST /analyze-json`, and `GET /analyze-json/{scan_id}` for frontend/API integrations.

## 4. Cloudflare Setup

- Point your domain to the Render service using the custom-domain flow in Render.
- In Cloudflare DNS, proxy the record after the Render custom domain is verified.
- Use Cloudflare SSL/TLS in `Full (strict)` mode so traffic is encrypted all the way to Render.
- Keep `SITE_URL` set to the final public HTTPS domain.

## 5. SEO And Discovery

FirmwareLens now exposes:

- `/robots.txt`
- `/sitemap.xml`
- `/ads.txt` when `ADS_TXT_CONTENT` is configured

This helps search engines discover the launch site and gives you a clean path for future AdSense or partner ad setup.

## 6. Local Smoke Test Before Launch

Run these before pushing:

```sh
pip install -r requirements.txt
pytest
python app.py
```

Then manually verify:

1. Home page loads with the login/guest panel.
2. Guest scan flow works.
3. Account registration and login work.
4. Support page opens without a 500.
5. PDF download works.
6. `/health`, `/robots.txt`, and `/sitemap.xml` all respond correctly.

## 7. Ad Revenue Advice

Do not place ads on the upload, result, or support workflow first. Keep the product pages trust-heavy and use ads later on content pages such as docs, guides, or tutorials.

If you later enable AdSense:

- publish a valid `ADS_TXT_CONTENT`
- keep `GA_MEASUREMENT_ID` enabled for traffic measurement
- confirm your CSP and page placement rules still match the ad provider requirements
