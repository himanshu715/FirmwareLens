# FirmwareLens Deployment Guide

This project can be launched quickly on Render, then placed behind Cloudflare for global delivery and DNS control.

## 1. Prepare The Repo

- Keep [requirements.txt](/C:/Users/Himan/Downloads/firmware-security-analyzer/requirements.txt) up to date.
- Use [Procfile](/C:/Users/Himan/Downloads/firmware-security-analyzer/Procfile) or [render.yaml](/C:/Users/Himan/Downloads/firmware-security-analyzer/render.yaml) for the web start command.
- Copy [.env.example](/C:/Users/Himan/Downloads/firmware-security-analyzer/.env.example) to your local environment and set real secrets before deploying.

## 2. Recommended Render Setup

The included [render.yaml](/C:/Users/Himan/Downloads/firmware-security-analyzer/render.yaml) assumes:

- `gunicorn app:app` for production serving
- `/health` as the health check path
- a persistent disk mounted at `/var/data`
- `RUNTIME_ROOT=/var/data/firmwarelens` so uploads, reports, scan results, and the SQLite database live on persistent storage

Important environment values:

- `FLASK_SECRET_KEY`: set to a strong random value
- `COOKIE_SECURE=1`: required for HTTPS deployments
- `SITE_URL=https://your-domain.example`: used for canonical URLs, sitemap generation, and robots output
- `GA_MEASUREMENT_ID`: optional, enables GA4 tracking
- `ADS_TXT_CONTENT`: optional, publishes `/ads.txt` when you are ready for ad networks
- `API_ACCESS_KEY`: optional, protects the FastAPI upload/analyze endpoints

## 3. Cloudflare Setup

- Point your domain to the Render service using the custom-domain flow in Render.
- In Cloudflare DNS, proxy the record after the Render custom domain is verified.
- Use Cloudflare SSL/TLS in `Full (strict)` mode so traffic is encrypted all the way to Render.
- Keep `SITE_URL` set to the final public HTTPS domain.

## 4. SEO And Discovery

FirmwareLens now exposes:

- `/robots.txt`
- `/sitemap.xml`
- `/ads.txt` when `ADS_TXT_CONTENT` is configured

This helps search engines discover the launch site and gives you a clean path for future AdSense or partner ad setup.

## 5. Local Smoke Test Before Launch

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

## 6. Ad Revenue Advice

Do not place ads on the upload, result, or support workflow first. Keep the product pages trust-heavy and use ads later on content pages such as docs, guides, or tutorials.

If you later enable AdSense:

- publish a valid `ADS_TXT_CONTENT`
- keep `GA_MEASUREMENT_ID` enabled for traffic measurement
- confirm your CSP and page placement rules still match the ad provider requirements
