# CyberShield AI – News Feed and Readability Update

## What changed

- Reworked the page background to a clean deep-navy gradient with subtle blue accents. The large hacker artwork is confined to feature/hero areas instead of sitting behind long text.
- Increased contrast on page cards, body text, descriptions and news status messages.
- Replaced the news page's generic official-site fallback links with individual CERT-In advisory cards.
- The backend now attempts to fetch the CERT-In 2026 advisory listing and extract individual advisory links.
- If CERT-In is temporarily unreachable or its page markup changes, the app shows a clearly labelled cached set of recent advisory references instead of leaving the page stuck on “Loading” or showing a generic link as news.
- Each “Read individual advisory” link opens the matching advisory in a new browser tab. The news listing itself remains inside CyberShield AI.
- Added request timeout, empty/error states, and a Try again action.

## Run on Windows

1. Extract the ZIP.
2. Open the extracted project folder in VS Code.
3. In Terminal 1, install frontend dependencies and start the backend:

   ```powershell
   cd backend
   python server.py
   ```

4. In Terminal 2, from the project root, install dependencies and start Vite:

   ```powershell
   npm install
   npm run dev
   ```

5. Open the localhost URL printed by Vite.
6. Open **Latest Cyber Crime News** and press **Refresh news** if needed.

The backend must remain running for the news feed. Its local API is `http://127.0.0.1:8000/cyber-news`; `http://127.0.0.1:8000/health` reports backend status.

## News freshness and limitations

- When the CERT-In listing is reachable and can be parsed, cards are populated from the live official listing.
- When the source cannot be reached, the page displays a clearly labelled cached set of recent CERT-In advisories with individual official article URLs. Cached entries are not represented as live updates.
- This is a published-advisory feed, not a live intrusion detector or an all-source news aggregator.
- External CERT-In website availability and its page markup are outside this app's control. Refresh after a temporary network issue.

## Environment configuration

The private `backend/.env` file is intentionally not included. If your project uses Google Safe Browsing, copy your existing private `.env` file into the new `backend` folder. Never share or upload the API key publicly.
