# CyberShield AI upgrade notes

## Start locally
1. Install dependencies: `npm install`
2. Start the React app: `npm run dev`
3. In a second terminal: `py backend/server.py`

## Optional environment setting
Copy `.env.example` to `.env.local` and set `VITE_API_BASE_URL` if the Python API is hosted somewhere other than `http://127.0.0.1:8000`.

## Important limitations
- URL detection uses heuristic indicators plus Google Safe Browsing when `SAFE_BROWSING_API_KEY` is configured on the Python server.
- If Safe Browsing is not configured or unavailable, the backend returns `UNVERIFIED` for URLs that do not otherwise trigger the local risk heuristics. It does not claim that an unchecked URL is safe.
- SMS/email analysis is a transparent keyword heuristic, not a trained AI or machine-learning classifier.
- QR checking currently means scanning a URL manually entered from a QR code. Camera-based QR image decoding is not implemented.
- Password strength checks run locally in the browser and are not sent to the backend or stored.
- Firestore history requires rules that restrict reads/writes to documents where `uid` matches the authenticated user's UID. An index may be requested for the combined `uid` and `timestamp` query; follow the Firebase Console link if one appears.
- The app is currently configured with a local Python API by default. A deployed frontend needs a publicly hosted API and a production `VITE_API_BASE_URL`.

## Additional experience upgrade (October 2026)
- Added QR image decoding to the URL scanner using the browser Barcode Detection API. Image decoding stays in the browser; decoded HTTP(S) URLs are placed in the URL field for review before scanning. Current Chrome/Edge support is recommended. Non-URL QR payloads are displayed as text and are not opened automatically.
- Expanded the security playbook with plain-language explanations and response steps for phishing, smishing/vishing, QR phishing, credential attacks, social engineering, malware/ransomware, payment scams, Wi-Fi/session risks, OTP scams and routine security hygiene.
- Scan results now show backend-provided URL reasons and message keyword indicators, plus the detection method and limitations where available.
- Retained the optional local password generator: cryptographically secure browser randomness, configurable 12–40 character length, character groups, and copy support. Generated passwords are not sent to the backend or stored in Firestore.
- Added responsive QR upload, result-explanation and awareness-guide styling.

QR scanning note: `BarcodeDetector` is a browser API and is not available in every browser. Use a recent Chrome or Edge browser; otherwise enter the URL manually. QR content is never auto-opened.
