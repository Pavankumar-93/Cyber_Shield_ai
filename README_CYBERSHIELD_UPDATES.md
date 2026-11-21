# CyberShield AI — Cyber Crime Hub update

## What changed
- Added Latest Cyber Crime News, Report Cyber Crime, Cyber Laws in India, and Victim Help Centre pages.
- Added a cinematic navy/blue cybersecurity hero image featuring a hooded laptop user, shield and lock. The same artwork is used in the dashboard and new page banners.
- Added a backend `/cyber-news` endpoint that fetches published CERT-In advisory links and falls back to official CERT-In pages if the feed is unavailable. The frontend refreshes while the news page is open.
- Existing Firebase authentication, URL/message scanning, QR image decoding, password checker/generator, and scan history source files were retained.

## Run on Windows
1. Extract this ZIP.
2. Open the extracted folder in VS Code.
3. In a terminal run `npm install`.
4. In a second terminal run `python backend/server.py`.
5. In another terminal run `npm run dev`.
6. Open the localhost URL printed by Vite.

## API key
The private `backend/.env` file is intentionally not included. Create `backend/.env` locally and add:
`SAFE_BROWSING_API_KEY=YOUR_EXISTING_KEY`
Do not share this key or upload it publicly. Restart the Python backend after editing the file.

## Notes
- The news page displays published advisories, not live attack detection.
- The reporting page links to official government services; CyberShield AI does not file complaints.
- The legal page is an educational overview, not legal advice. Verify current law text and notifications through official sources.
