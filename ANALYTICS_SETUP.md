# FirmwareLens Global Traction Tracking

Use this guide to understand how popular FirmwareLens is across countries, not just how many visits it gets.

## 1. Set Up GA4

Create a Google Analytics 4 property and set the environment variable:

```powershell
$env:GA_MEASUREMENT_ID="G-XXXXXXXXXX"
```

Then restart the app.

When `GA_MEASUREMENT_ID` is set, the UI sends GA4 events from the main user flow.

## 2. Events Already Wired In

FirmwareLens now emits or queues these events:

- `login_attempt`
- `register_attempt`
- `guest_login_attempt`
- `login`
- `sign_up`
- `guest_login`
- `scan_started`
- `scan_completed`
- `report_downloaded`
- `support_opened`
- `bot_chat_submitted`
- `bot_chat_used`
- `field_issue_submitted`
- `field_issue_reported`
- `field_guidance_generated`
- `feedback_attempt`
- `feedback_submitted`

## 3. What To Measure By Country

Use GA4 reports or explorations to break these down by country:

- Users
- New users
- Guest logins
- Signups
- Completed scans
- PDF downloads
- Support opens
- Bot chat usage
- Field issue reports

These are much better popularity signals than page views alone.

## 4. Best Weekly Dashboard

Track this table every week:

- Country
- Visitors
- Guest sessions
- Signups
- Completed scans
- PDF downloads
- Support opens
- Returning users
- Paid conversions

## 5. How To Read Real Popularity

FirmwareLens is becoming genuinely global when:

- multiple countries produce completed scans, not just visits
- repeat users appear outside one home market
- branded search starts rising
- support usage and report downloads grow with scans
- revenue starts coming from more than one country

## 6. Supporting Tools

Use these alongside GA4:

- Google Search Console for country-level organic search and branded search growth
- Google Trends for market-term interest and brand search over time

## 7. Recommended First KPI Set

If you want one simple popularity score, weight it like this:

- `40%` completed scans
- `25%` repeat users
- `20%` report downloads
- `15%` signups

This gives a much more honest picture than raw traffic.
