from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urljoin
import json
import os
import re
import socket
import urllib.request
from pathlib import Path
from html.parser import HTMLParser
from html import unescape


def load_local_env():
    """Load backend/.env without requiring an extra Python package."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_local_env()
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")


def check_safe_browsing(url):
    """Return a status and threat flag; API failures are not treated as clean results."""
    if not SAFE_BROWSING_API_KEY:
        print("Safe Browsing unavailable: API key is not configured")
        return "UNAVAILABLE", False

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?"
        + urlencode({"key": SAFE_BROWSING_API_KEY})
    )
    payload = {
        "client": {"clientId": "CyberShieldAI", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("matches"):
            print("Safe Browsing: THREAT_FOUND")
            return "THREAT_FOUND", True
        print("Safe Browsing: NO_THREAT_FOUND")
        return "NO_THREAT_FOUND", False
    except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, ValueError) as error:
        print("Safe Browsing request failed:", error)
        return "UNAVAILABLE", False


def analyze_url_locally(url):
    words = (
        "login", "verify", "account", "password", "update",
        "free", "winner", "prize", "secure", "bank"
    )
    lowered = url.lower()
    reasons = [f"Potentially sensitive term in URL: {word}" for word in words if word in lowered]
    score = len(reasons) * 10
    if not lowered.startswith("https://"):
        score += 20
        reasons.append("URL does not use HTTPS")
    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long")
    return min(score, 100), reasons


def check_message(message):
    words = (
        "otp", "urgent", "click here", "verify", "winner", "prize",
        "lottery", "bank", "password", "account blocked", "claim now", "free"
    )
    matched = [word for word in words if word in message.lower()]
    score = min(len(matched) * 10, 100)
    verdict = "SCAM" if score >= 40 else "SUSPICIOUS" if score >= 20 else "SAFE"
    return verdict, score, matched




class AdvisoryLinkParser(HTMLParser):
    """Extract advisory links from CERT-In pages even when markup is not table-based."""
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_href = None
        self.current_text = []
        self.block_stack = []
        self.block_text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag in ("tr", "li", "article", "div", "p"):
            self.block_stack.append(tag)
            self.block_text.append([])
        if tag == "a":
            self.current_href = attrs.get("href", "")
            self.current_text = []

    def handle_data(self, data):
        text = " ".join(data.split())
        if not text:
            return
        if self.current_href is not None:
            self.current_text.append(text)
        for block in self.block_text:
            block.append(text)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "a" and self.current_href is not None:
            href = self.current_href.strip()
            title = " ".join(self.current_text).strip()
            context = " ".join(self.block_text[-1]).strip() if self.block_text else title
            if href and ("VLCODE=" in href or "PUBVLNOTES" in href):
                self.links.append({"href": href, "title": title, "context": context})
            self.current_href = None
            self.current_text = []
        if tag in ("tr", "li", "article", "div", "p") and self.block_stack:
            # Keep parent text available to anchors that follow their title/date labels.
            if self.block_stack[-1] == tag:
                self.block_stack.pop()
                self.block_text.pop()


class CyberShieldServer(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/cyber-news":
            source_url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year=2026"
            cached_items = [
                {"title": "Escalation of AI-Driven Attacks on BFSI Entities by Threat Actor CRAFTY FALCON", "summary": "CERT-In reported an increase in AI-assisted attacks targeting banking and financial services entities. Review the official advisory for affected systems and recommended mitigations.", "date": "04 Nov 2026", "category": "HIGH ALERT", "url": "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0058&pageid=PUBVLNOTES02"},
                {"title": "Multiple vulnerabilities in GoAhead Web Server", "summary": "A CERT-In advisory covering multiple vulnerabilities in GoAhead Web Server. Administrators should review the official notice and apply vendor-recommended updates.", "date": "28 Oct 2026", "category": "VULNERABILITY", "url": "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0057&pageid=PUBVLNOTES02"},
                {"title": "Multiple vulnerabilities in Apple Products", "summary": "CERT-In published a security advisory covering multiple vulnerabilities in Apple products. Check the advisory for affected versions and updates.", "date": "27 Oct 2026", "category": "VULNERABILITY", "url": "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0056&pageid=PUBVLNOTES02"},
                {"title": "Out-of-Bounds Write Vulnerability in Google Brotli Decoder", "summary": "The advisory describes an out-of-bounds write vulnerability in the Brotli decoder. Consult the official notice for technical details and remediation.", "date": "27 Oct 2026", "category": "VULNERABILITY", "url": "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0055&pageid=PUBVLNOTES02"},
                {"title": "Compromise of LiteLLM PyPI Package and Docker Images", "summary": "CERT-In reported a compromise involving the LiteLLM PyPI package and Docker images. Review the advisory for exposure checks and response guidance.", "date": "23 Oct 2026", "category": "SUPPLY-CHAIN ALERT", "url": "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0053&pageid=PUBVLNOTES02"},
            ]
            try:
                req = urllib.request.Request(source_url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "close",
                })
                with urllib.request.urlopen(req, timeout=12) as response:
                    html = response.read(3_000_000).decode("utf-8", errors="replace")
                parser = AdvisoryLinkParser()
                parser.feed(html)
                items, seen = [], set()
                for link in parser.links:
                    href = urljoin("https://www.cert-in.org.in/", link["href"])
                    code_match = re.search(r"VLCODE=([A-Z0-9-]+)", href, re.I)
                    context = " ".join((link.get("context", "") + " " + link.get("title", "")).split())
                    if not code_match or href in seen:
                        continue
                    code = code_match.group(1)
                    # CERT-In page may render a short 'View' anchor; use nearby row text when available.
                    title = re.sub(r"\s+", " ", context).strip(" |–-\t")
                    title = re.sub(r"Home\s+Advisories?", "", title, flags=re.I).strip(" |–-\t")
                    if len(title) < 12 or title.lower() in ("view", "read more", "details"):
                        title = link.get("title") or code
                    date_match = re.search(r"\b(\d{1,2}\s+[A-Za-z]+\s+20\d{2})\b", context)
                    date = date_match.group(1) if date_match else "CERT-In advisory"
                    items.append({"title": title[:220], "summary": "Official CERT-In security advisory. Open the individual notice for affected products, severity and recommended mitigation.", "date": date, "category": "SECURITY ADVISORY", "url": href})
                    seen.add(href)
                if items:
                    self.send_json({"items": items[:12], "source": "CERT-In", "fetched": True, "cached": False, "message": "Official advisories loaded."})
                else:
                    self.send_json({"items": cached_items, "source": "CERT-In", "fetched": False, "cached": True, "message": "Live page format could not be parsed; showing recent verified advisory references."})
            except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, UnicodeError) as error:
                print("CERT-In news feed unavailable:", error)
                self.send_json({"items": cached_items, "source": "CERT-In", "fetched": False, "cached": True, "message": "CERT-In could not be reached right now; showing recent published advisories with direct article links."})
            return
        if self.path in ("/", "/health"):
            self.send_json({
                "status": "ok",
                "service": "CyberShield AI Python API",
                "safe_browsing_configured": bool(SAFE_BROWSING_API_KEY),
                "endpoints": ["/check-url (POST)", "/check-message (POST)", "/cyber-news (GET)"],
            })
        else:
            self.send_json({"error": "Endpoint not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 100000:
            raise ValueError("Request body is empty or too large")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_POST(self):
        if self.path == "/check-url":
            try:
                data = self.read_json_body()
                url = str(data.get("url", "")).strip()
                parsed = urlsplit(url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    self.send_json({"error": "Enter a valid URL starting with http:// or https://"}, 400)
                    return

                google_status, google_threat = check_safe_browsing(url)
                local_score, reasons = analyze_url_locally(url)

                if google_threat:
                    verdict, risk_score = "PHISHING", 100
                    reasons.append("Google Safe Browsing reported a known threat")
                elif local_score >= 40:
                    verdict, risk_score = "PHISHING", local_score
                elif local_score >= 20:
                    verdict, risk_score = "SUSPICIOUS", local_score
                elif google_status == "UNAVAILABLE":
                    verdict, risk_score = "UNVERIFIED", local_score
                    reasons.append("External reputation check was unavailable")
                else:
                    verdict, risk_score = "SAFE", local_score

                self.send_json({
                    "url": url,
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "google_safe_browsing": google_status,
                    "local_analysis": "COMPLETED",
                    "reasons": reasons,
                    "disclaimer": "No known threat detected is not a guarantee that this URL is safe.",
                })
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
                self.send_json({"error": str(error)}, 400)
            except Exception as error:
                print("URL server error:", error)
                self.send_json({"error": "Internal server error"}, 500)
            return

        if self.path == "/check-message":
            try:
                data = self.read_json_body()
                message = str(data.get("message", "")).strip()
                if not message:
                    self.send_json({"error": "Message is required"}, 400)
                    return
                verdict, risk_score, matched = check_message(message)
                self.send_json({
                    "message": message,
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "matched_indicators": matched,
                    "method": "Keyword-based heuristic; not an AI model",
                })
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
                self.send_json({"error": str(error)}, 400)
            except Exception as error:
                print("Message server error:", error)
                self.send_json({"error": "Internal server error"}, 500)
            return

        self.send_json({"error": "Endpoint not found"}, 404)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), CyberShieldServer)
    print("\nCyberShield AI API: http://127.0.0.1:8000")
    print("Google Safe Browsing: " + ("configured" if SAFE_BROWSING_API_KEY else "UNAVAILABLE (API key missing)"))
    print("Endpoints: /health, /check-url, /check-message\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()
