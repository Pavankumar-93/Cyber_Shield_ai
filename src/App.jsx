import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";
import Auth from "./Auth";
import { auth, db } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import {
  addDoc, collection, getDocs, query, serverTimestamp, where,
} from "firebase/firestore";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const NAV_ITEMS = [
  { id: "overview", icon: "◫", label: "Overview" },
  { id: "url", icon: "↗", label: "URL scanner" },
  { id: "message", icon: "✉", label: "Message scanner" },
  { id: "password", icon: "⌑", label: "Password check" },
  { id: "history", icon: "◷", label: "Scan history" },
  { id: "news", icon: "▣", label: "Latest Cyber Crime News" },
  { id: "report", icon: "⚑", label: "Report Cyber Crime" },
  { id: "laws", icon: "⚖", label: "Cyber Laws in India" },
  { id: "victim", icon: "✚", label: "Victim Help Centre" },
  { id: "awareness", icon: "ⓘ", label: "Security Guide" },
];

function riskTone(verdict = "") {
  const value = verdict.toUpperCase();
  if (["SAFE", "CLEAN", "NO THREAT"].includes(value)) return "safe";
  if (["UNKNOWN", "UNAVAILABLE", "ERROR"].includes(value)) return "unknown";
  if (["SUSPICIOUS", "WARNING"].includes(value)) return "warning";
  return "danger";
}

function RiskBadge({ verdict }) {
  return <span className={`risk-badge ${riskTone(verdict)}`}>{verdict || "UNKNOWN"}</span>;
}

function App() {
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [active, setActive] = useState("overview");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [url, setUrl] = useState("");
  const [qrStatus, setQrStatus] = useState("");
  const [qrBusy, setQrBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [generatorLength, setGeneratorLength] = useState(20);
  const [genUpper, setGenUpper] = useState(true);
  const [genLower, setGenLower] = useState(true);
  const [genNumbers, setGenNumbers] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [notice, setNotice] = useState("");

  useEffect(() => onAuthStateChanged(auth, (nextUser) => {
    setUser(nextUser);
    setAuthReady(true);
  }), []);

  const loadHistory = useCallback(async (currentUser) => {
    if (!currentUser) { setHistory([]); return; }
    setHistoryLoading(true);
    try {
      const q = query(
        collection(db, "scanHistory"),
        where("uid", "==", currentUser.uid)
      );
      const snap = await getDocs(q);
      const rows = snap.docs.map((item) => ({ id: item.id, ...item.data() }));
      rows.sort((a, b) => {
        const aTime = a.timestamp?.toMillis?.() || 0;
        const bTime = b.timestamp?.toMillis?.() || 0;
        return bTime - aTime;
      });
      setHistory(rows);
      setNotice("");
    } catch (error) {
      console.error("History loading error:", error);
      setNotice("Scan history could not be loaded. Check your Firestore rules and any index request in the browser console.");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    if (authReady) loadHistory(user);
  }, [authReady, user, loadHistory]);

  const stats = useMemo(() => ({
    total: history.length,
    threats: history.filter((item) => ["PHISHING", "SCAM", "MALICIOUS", "DANGEROUS"].includes(String(item.verdict).toUpperCase())).length,
    safe: history.filter((item) => String(item.verdict).toUpperCase() === "SAFE").length,
  }), [history]);

  const saveScan = async (type, input, data) => {
    if (!auth.currentUser) return;
    try {
      await addDoc(collection(db, "scanHistory"), {
        uid: auth.currentUser.uid,
        type,
        input,
        verdict: data.verdict || "UNKNOWN",
        risk_score: Number(data.risk_score ?? 0),
        timestamp: serverTimestamp(),
      });
      await loadHistory(auth.currentUser);
    } catch (error) {
      console.error("Scan history save failed:", error);
      setNotice("Your scan completed, but its history could not be saved. Check Firestore permissions.");
    }
  };

  const decodeQrImage = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) { setQrStatus("Please choose an image file."); return; }
    if (file.size > 10 * 1024 * 1024) { setQrStatus("Image is too large. Choose an image under 10 MB."); return; }
    if (!("BarcodeDetector" in window)) { setQrStatus("QR image decoding is not supported by this browser. Open CyberShield in the latest Chrome or Edge, or enter the decoded URL manually."); return; }
    setQrBusy(true); setQrStatus("Reading QR code locally…");
    try {
      const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const codes = await detector.detect(bitmap);
      bitmap.close?.(); setQrBusy(false);
      if (!codes.length || !codes[0].rawValue) { setQrStatus("No readable QR code found. Try a sharper image with the full code visible."); return; }
      const payload = codes[0].rawValue.trim();
      if (/^https?:\/\//i.test(payload)) {
        setUrl(payload); setQrStatus("QR link decoded. Review the address below, then scan it.");
      } else {
        setQrStatus(`QR decoded, but it is not a web link: ${payload.slice(0, 180)}`);
      }
    } catch { setQrBusy(false); setQrStatus("Could not decode this image. Try a clearer QR image or use the latest Chrome/Edge."); }
  };

  const runScan = async (kind) => {
    const input = kind === "url" ? url.trim() : message.trim();
    if (!input) {
      setResult({ error: kind === "url" ? "Enter a URL to scan." : "Paste a message to scan." });
      return;
    }
    setBusy(true);
    setResult(null);
    setNotice("");
    try {
      const response = await fetch(`${API_BASE}/${kind === "url" ? "check-url" : "check-message"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(kind === "url" ? { url: input } : { message: input }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Server returned ${response.status}`);
      setResult({ ...data, kind });
      await saveScan(kind === "url" ? "Website" : "SMS / Email", input, data);
    } catch (error) {
      setResult({ error: `${error.message}. Make sure the Python backend is running and the API address is correct.` });
    } finally {
      setBusy(false);
    }
  };

  const passwordReport = useMemo(() => {
    if (!password) return null;
    let score = 0;
    const checks = [
      [password.length >= 12, "At least 12 characters"],
      [/[A-Z]/.test(password), "An uppercase letter"],
      [/[a-z]/.test(password), "A lowercase letter"],
      [/[0-9]/.test(password), "A number"],
      [/[^A-Za-z0-9]/.test(password), "A special character"],
      [!/(.)\1{2,}/.test(password), "No repeated character pattern"],
    ];
    score = checks.filter(([ok]) => ok).length;
    return { score, checks, label: score <= 2 ? "Weak" : score <= 4 ? "Fair" : score === 5 ? "Good" : "Strong" };
  }, [password]);

  const generatePassword = () => {
    const groups = [
      genUpper ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
      genLower ? "abcdefghijkmnopqrstuvwxyz" : "",
      genNumbers ? "23456789" : "",
      genSymbols ? "!@#$%^&*()-_=+[]{}:,.?" : "",
    ].filter(Boolean);
    if (!groups.length) {
      setCopyStatus("Choose at least one character type.");
      return;
    }
    const alphabet = groups.join("");
    const randomIndex = (max) => {
      const limit = Math.floor(256 / max) * max;
      const bytes = new Uint8Array(1);
      let value;
      do { crypto.getRandomValues(bytes); value = bytes[0]; } while (value >= limit);
      return value % max;
    };
    const chars = groups.map((group) => group[randomIndex(group.length)]);
    while (chars.length < generatorLength) chars.push(alphabet[randomIndex(alphabet.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomIndex(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    setGeneratedPassword(chars.join(""));
    setCopyStatus("");
  };

  const copyGeneratedPassword = async () => {
    if (!generatedPassword) return;
    try {
      await navigator.clipboard.writeText(generatedPassword);
      setCopyStatus("Copied. Store it in a trusted password manager.");
    } catch {
      setCopyStatus("Clipboard access unavailable. Select and copy the password manually.");
    }
  };

  const resetResult = () => setResult(null);
  const choose = (id) => { setActive(id); resetResult(); setNotice(""); };

  const handleSignOut = async () => {
    try {
      await signOut(auth);
      setHistory([]);
      setResult(null);
      setNotice("You have been signed out successfully.");
    } catch (error) {
      console.error("Sign out failed:", error);
      setNotice("Could not sign out. Please check your connection and try again.");
    }
  };

  if (!authReady) return <div className="boot-screen"><div className="brand-mark">✦</div><p>Initializing CyberShield…</p></div>;

  return (
    <div className="shell">
      <aside className="sidebar" style={{ overflowY: "auto", overscrollBehavior: "contain" }}>
        <a className="brand" href="#overview" onClick={() => choose("overview")}>
          <span className="brand-icon">✦</span>
          <span>CyberShield<span className="brand-ai"> AI</span><small>THREAT INTELLIGENCE</small></span>
        </a>
        <div className="side-label">WORKSPACE</div>
        <nav className="side-nav">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} className={active === item.id ? "nav-item active" : "nav-item"} onClick={() => choose(item.id)}>
              <span className="nav-icon">{item.icon}</span>{item.label}
              {item.id === "history" && history.length > 0 && <span className="nav-count">{history.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom" style={{ flexShrink: 0, paddingBottom: 12 }}>
          <div className="system-card"><span className="status-dot" /><div><b>Protection systems</b><small>Local scanner interface ready</small></div></div>
          <button className="help-link" onClick={() => choose("awareness")}>ⓘ Security best practices</button>
          {user ? (
            <section
              aria-label="Account options"
              style={{ marginTop: 14, padding: 13, border: "1px solid rgba(85,214,232,.42)", borderRadius: 10, background: "linear-gradient(145deg, rgba(22,43,67,.98), rgba(13,25,41,.98))", minWidth: 0, boxShadow: "0 8px 24px rgba(0,0,0,.18)" }}
            >
              <div style={{ color: "#7f94ad", fontSize: 9, letterSpacing: 1.4, fontWeight: 700, marginBottom: 10 }}>ACCOUNT</div>
              <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0, marginBottom: 12 }}>
                <span className="avatar" aria-hidden="true">{(user.email || "U")[0].toUpperCase()}</span>
                <span style={{ minWidth: 0, color: "#eaf2ff", fontSize: 10, lineHeight: 1.4, overflowWrap: "anywhere" }}>
                  <strong style={{ display: "block", fontSize: 11, marginBottom: 2 }}>Signed in</strong>
                  {user.email || "Account active"}
                </span>
              </div>
              <button
                type="button"
                onClick={handleSignOut}
                style={{ width: "100%", minHeight: 38, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, border: "1px solid rgba(255,126,139,.45)", borderRadius: 7, background: "rgba(130,42,57,.2)", color: "#ffabb4", fontSize: 11, fontWeight: 700, cursor: "pointer" }}
              >
                <span aria-hidden="true">⇥</span> Log out of account
              </button>
            </section>
          ) : (
            <button className="login-side" onClick={() => setShowAuth(true)}>Sign in / Create account</button>
          )}
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div><span className="breadcrumb">Workspace</span><span className="crumb-sep">/</span><b>{NAV_ITEMS.find((n) => n.id === active)?.label || "Security guide"}</b></div>
          <div className="topbar-right"><span className="environment"><i /> SYSTEM ONLINE</span>{user ? <span className="top-user">{user.email}</span> : <button className="btn btn-outline btn-small" onClick={() => setShowAuth(true)}>Sign in</button>}</div>
        </header>

        <div className="content">
          {notice && <div className="notice"><span>!</span>{notice}<button onClick={() => setNotice("")}>×</button></div>}

          {active === "overview" && <>
            <section className="welcome-row">
              <div><div className="eyebrow"><span className="eyebrow-line" /> SECURITY COMMAND CENTER</div><h1>Your digital world,<br /><em>under protection.</em></h1><p className="lead">Inspect suspicious links and messages before they become a threat.</p><button className="btn btn-primary" onClick={() => choose("url")}>Start a security scan <span>→</span></button></div>
              <div className="hero-art" aria-label="Abstract cybersecurity shield illustration"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="shield-glow"><div className="shield-shape">✦</div></div><span className="float-tag tag-one">URL MONITORING</span><span className="float-tag tag-two"><i /> THREAT RADAR ACTIVE</span><span className="art-cross cross-one">+</span><span className="art-cross cross-two">+</span></div>
            </section>
            <section className="metric-grid">
              <Metric label="TOTAL SCANS" value={stats.total} icon="⌁" hint="Your saved scan history" />
              <Metric label="THREATS FLAGGED" value={stats.threats} icon="⚑" hint="Potential risks identified" />
              <Metric label="SAFE RESULTS" value={stats.safe} icon="✓" hint="Scans marked safe" />
              <Metric label="ACCOUNT STATUS" value={user ? "Active" : "Guest"} icon="◉" hint={user ? "History sync enabled" : "Sign in to save scans"} />
            </section>
            <section className="section-block"><div className="section-heading"><div><div className="eyebrow">YOUR SECURITY TOOLS</div><h2>Choose what to inspect</h2></div><span className="muted">01 — 04 / SCANNERS</span></div>
              <div className="tool-grid">
                <ToolCard icon="↗" tag="WEB SECURITY" title="URL threat scanner" desc="Check suspicious websites for phishing indicators and known threats." onClick={() => choose("url")} />
                <ToolCard icon="✉" tag="MESSAGE SECURITY" title="SMS & email scanner" desc="Review messages for common scam and social-engineering signals." onClick={() => choose("message")} />
                <ToolCard icon="⌑" tag="ACCOUNT SECURITY" title="Password strength" desc="Evaluate password composition and get practical improvements." onClick={() => choose("password")} />
                <ToolCard icon="◷" tag="ACTIVITY" title="Scan history" desc="Review your previous checks and their risk assessments." onClick={() => choose("history")} />
              </div>
            </section>
            <section className="bottom-banner"><div><div className="eyebrow">STAY ONE STEP AHEAD</div><h3>Pause. Inspect. Then click.</h3><p>Unexpected urgency is a common tactic used in phishing and online scams.</p></div><span className="banner-symbol">✳</span></section>
          </>}

          {active === "url" && <ScannerPage eyebrow="WEB SECURITY / 01" title="URL threat scanner" description="Enter a website address to inspect it for known threats and suspicious URL patterns." icon="↗">
            <form onSubmit={(e) => { e.preventDefault(); runScan("url"); }} className="scan-form">
              <label htmlFor="url-input">WEBSITE ADDRESS</label><div className="input-wrap"><span>↗</span><input id="url-input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" type="text" autoComplete="url" /></div>
              <div className="qr-upload"><div><b>Or scan a QR code image</b><small>Upload a PNG, JPG or WebP image. Decoding happens in your browser.</small></div><label className="btn btn-outline qr-pick" htmlFor="qr-image">{qrBusy ? "Reading…" : "Choose QR image"}</label><input id="qr-image" type="file" accept="image/*" onChange={decodeQrImage} disabled={qrBusy} /></div>
              {qrStatus && <p className="qr-status" role="status">{qrStatus}</p>}
              <button className="btn btn-primary scan-submit" disabled={busy}>{busy ? <><span className="spinner" /> Analyzing…</> : <>Analyze website <span>→</span></>}</button>
            </form>
            <p className="privacy-note">⌑ Do not enter passwords or private information. A scan is an assessment, not a guarantee of safety.</p>
            <ResultPanel result={result} />
          </ScannerPage>}

          {active === "message" && <ScannerPage eyebrow="MESSAGE SECURITY / 02" title="SMS & email scanner" description="Paste a suspicious message to identify common scam signals and pressure tactics." icon="✉">
            <form onSubmit={(e) => { e.preventDefault(); runScan("message"); }} className="scan-form">
              <label htmlFor="message-input">MESSAGE CONTENT</label><textarea id="message-input" className="message-input" value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Paste the SMS or email text here…" rows="7" />
              <button className="btn btn-primary scan-submit" disabled={busy}>{busy ? <><span className="spinner" /> Checking…</> : <>Analyze message <span>→</span></>}</button>
            </form>
            <p className="privacy-note">⌑ Remove personal details before pasting messages. Keyword-based detection can miss sophisticated scams.</p>
            <ResultPanel result={result} />
          </ScannerPage>}

          {active === "password" && <ScannerPage eyebrow="ACCOUNT SECURITY / 03" title="Password strength" description="Check password composition locally in your browser. Your password is not sent to the Python scanner or saved to history." icon="⌑">
            <div className="scan-form"><label htmlFor="password-input">PASSWORD TO CHECK</label><div className="input-wrap"><span>⌑</span><input id="password-input" type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter a password to evaluate" /><button className="show-pass" type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button></div>
              {passwordReport && <div className="password-report"><div className="password-score"><div><small>STRENGTH ESTIMATE</small><b>{passwordReport.label}</b></div><strong>{passwordReport.score}/6</strong></div><div className="strength-track"><span style={{ width: `${passwordReport.score / 6 * 100}%` }} /></div><div className="check-grid">{passwordReport.checks.map(([ok, text]) => <span className={ok ? "check-ok" : "check-no"} key={text}>{ok ? "✓" : "○"} {text}</span>)}</div></div>}
            </div>
            <p className="privacy-note">⌑ This is a basic composition check, not a password breach check. Never reuse passwords across sites.</p>
            <section className="generator-panel" aria-label="Password generator">
              <div className="generator-heading"><div><small>OPTIONAL TOOL</small><h3>Generate a strong password</h3><p>Create a random password locally in this browser.</p></div><span className="generator-icon">✧</span></div>
              <div className="generator-length"><label htmlFor="generator-length">LENGTH <b>{generatorLength} characters</b></label><input id="generator-length" type="range" min="12" max="40" value={generatorLength} onChange={(e) => setGeneratorLength(Number(e.target.value))} /></div>
              <div className="generator-options">
                <label><input type="checkbox" checked={genUpper} onChange={(e) => setGenUpper(e.target.checked)} /> Uppercase</label>
                <label><input type="checkbox" checked={genLower} onChange={(e) => setGenLower(e.target.checked)} /> Lowercase</label>
                <label><input type="checkbox" checked={genNumbers} onChange={(e) => setGenNumbers(e.target.checked)} /> Numbers</label>
                <label><input type="checkbox" checked={genSymbols} onChange={(e) => setGenSymbols(e.target.checked)} /> Symbols</label>
              </div>
              <button className="btn btn-primary scan-submit" type="button" onClick={generatePassword}>Generate password <span>✧</span></button>
              {generatedPassword && <div className="generated-output"><label htmlFor="generated-password">GENERATED PASSWORD</label><div className="input-wrap"><input id="generated-password" type="text" readOnly value={generatedPassword} onFocus={(e) => e.target.select()} /><button className="show-pass" type="button" onClick={copyGeneratedPassword}>Copy</button></div><p className="privacy-note">Generated with the browser's cryptographically secure random-number generator. It is not sent to the server or saved.</p></div>}
              {copyStatus && <p className="generator-status" role="status">{copyStatus}</p>}
            </section>
          </ScannerPage>}

          {active === "history" && <section className="page-section"><div className="eyebrow">ACTIVITY LOG / 04</div><h1 className="page-title">Scan history</h1><p className="lead">A record of your recent security checks.</p>{!user ? <div className="empty-state"><span>◷</span><h3>Sign in to view your history</h3><p>Saved scans are private to your account.</p><button className="btn btn-primary" onClick={() => setShowAuth(true)}>Sign in / Register</button></div> : historyLoading ? <div className="empty-state">Loading your scans…</div> : history.length === 0 ? <div className="empty-state"><span>⌁</span><h3>No scans saved yet</h3><p>Your completed URL and message scans will appear here.</p><button className="btn btn-primary" onClick={() => choose("url")}>Run your first scan</button></div> : <div className="history-table"><div className="history-head"><span>TYPE / INPUT</span><span>VERDICT</span><span>RISK</span></div>{history.map((item) => <div className="history-row" key={item.id}><div><b>{item.type}</b><small>{item.input}</small></div><RiskBadge verdict={item.verdict} /><strong>{item.risk_score ?? "—"}<small>/100</small></strong></div>)}</div>}</section>}

          {active === "news" && <section className="page-section" style={{ width: "100%", maxWidth: "1120px", margin: "0 auto", padding: "clamp(18px, 3vw, 36px)", boxSizing: "border-box", color: "#eaf2ff" }}>
            <div style={{ color: "#38d9f5", fontSize: "11px", fontWeight: 800, letterSpacing: "2px", marginBottom: "14px" }}>THREAT INTELLIGENCE / OFFICIAL NEWS</div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "24px", flexWrap: "wrap", marginBottom: "28px" }}>
              <div style={{ flex: "1 1 520px", minWidth: 0 }}>
                <h1 className="page-title" style={{ margin: "0 0 14px", lineHeight: 1.12, textAlign: "left" }}>Latest Cyber Crime News</h1>
                <p className="lead" style={{ margin: 0, maxWidth: "720px", lineHeight: 1.7, textAlign: "left" }}>Choose an official source below to view the latest cybersecurity advisories, alerts and updates. Each button opens the original government page in a new tab.</p>
              </div>
              <div aria-hidden="true" style={{ width: "76px", height: "76px", flex: "0 0 76px", display: "grid", placeItems: "center", borderRadius: "20px", border: "1px solid #155a78", background: "linear-gradient(145deg, #102b43, #101c35)", color: "#39d9f5", fontSize: "34px", boxShadow: "0 12px 32px #02081766" }}>▣</div>
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px", padding: "14px 16px", marginBottom: "22px", border: "1px solid #1d4563", borderRadius: "12px", background: "#0d1d32" }}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "9px", color: "#7cf5c3", fontSize: "11px", fontWeight: 800, letterSpacing: "1.4px" }}><i style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "#39d99b", boxShadow: "0 0 10px #39d99b" }} /> OFFICIAL GOVERNMENT SOURCES</span>
              <span style={{ color: "#a9bfd8", fontSize: "13px" }}>External links · No backend connection required</span>
            </div>

            <h2 style={{ margin: "0 0 18px", color: "#f1f6ff", fontSize: "clamp(20px, 2vw, 25px)", lineHeight: 1.3, textAlign: "left" }}>Official cyber security updates</h2>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 340px), 1fr))", gap: "18px", alignItems: "stretch" }}>
              {[
                { icon: "▤", label: "CERT-In · ADVISORIES", title: "Latest Security Advisories", description: "Browse CERT-In's official advisories, including newly reported vulnerabilities, malware campaigns and cyber threat warnings.", button: "Open latest advisories", url: "https://cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year=2026" },
                { icon: "◉", label: "CERT-In · CURRENT ACTIVITIES", title: "Current Cyber Threat Updates", description: "See CERT-In's current activity notices and summaries of emerging security issues affecting users and organisations.", button: "View current updates", url: "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBWEL03" },
                { icon: "⚠", label: "CERT-In · SECURITY ALERTS", title: "Latest Security Alerts", description: "Visit CERT-In for security alerts, vulnerability notes, advisories and cyber-security awareness resources.", button: "Open security alerts", url: "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBWEL01" },
                { icon: "⌕", label: "CERT-In · ADVISORY ARCHIVE", title: "Previous Year Advisories", description: "Browse the official advisory archive and select a year to find earlier cybersecurity publications.", button: "Browse advisory archive", url: "https://cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST" }
              ].map((item) => (
                <article key={item.title} style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: "12px", minWidth: 0, padding: "22px", border: "1px solid #1b4b70", borderRadius: "16px", background: "linear-gradient(145deg, #102744 0%, #0b1a30 100%)", boxShadow: "0 12px 28px #02081755", textAlign: "left", boxSizing: "border-box" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: "44px", height: "44px", borderRadius: "12px", background: "#103e5b", color: "#48dcfa", fontSize: "23px" }}>{item.icon}</div>
                  <div style={{ color: "#5edff5", fontSize: "10px", fontWeight: 800, letterSpacing: "1.2px", lineHeight: 1.5 }}>{item.label}</div>
                  <h3 style={{ margin: 0, color: "#f2f7ff", fontSize: "19px", lineHeight: 1.35, textAlign: "left" }}>{item.title}</h3>
                  <p style={{ margin: 0, color: "#b9cbe0", fontSize: "14px", lineHeight: 1.7, flex: "1 1 auto", textAlign: "left" }}>{item.description}</p>
                  <a href={item.url} target="_blank" rel="noopener noreferrer" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: "8px", marginTop: "6px", padding: "11px 16px", minHeight: "42px", borderRadius: "9px", background: "linear-gradient(100deg, #17a9c8, #3979e8)", color: "#ffffff", fontSize: "13px", fontWeight: 750, textDecoration: "none", boxSizing: "border-box" }}>{item.button} ↗</a>
                </article>
              ))}
            </div>

            <div style={{ marginTop: "22px", padding: "18px 20px", border: "1px solid #24415d", borderRadius: "12px", background: "#0b1a2d", color: "#b9cbe0", lineHeight: 1.7, fontSize: "13px", textAlign: "left" }}>
              <strong style={{ display: "block", color: "#eaf2ff", marginBottom: "5px" }}>About these links</strong>
              These buttons open official CERT-In pages in a new browser tab. CyberShield AI does not automatically fetch or reproduce external news, so this page remains usable even if the Python backend is stopped. Check the publication date and details on the official source.
            </div>
            <p style={{ margin: "14px 0 0", color: "#8fa9c5", fontSize: "12px", lineHeight: 1.6, textAlign: "left" }}>These are official advisory and security-update pages, not real-time attack detection on your device.</p>
          </section>}

          {active === "report" && <section className="page-section">
            <div className="eyebrow">OFFICIAL RESPONSE / INDIA</div><h1 className="page-title">Report Cyber Crime</h1><p className="lead">Use official government channels to report online fraud and cybercrime.</p>
            <div className="emergency-grid"><article className="emergency-card"><span className="hub-icon">☎</span><div><small>FINANCIAL CYBER FRAUD HELPLINE</small><strong>1930</strong><p>Call immediately if money has been lost through an online or digital payment fraud.</p></div></article><article className="hub-card portal-card"><span className="hub-icon">↗</span><div><small>NATIONAL CYBER CRIME REPORTING PORTAL</small><h3>File a complaint online</h3><p>Report financial fraud and other cybercrime through the Government of India's portal.</p><a className="btn btn-primary" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">Open reporting portal ↗</a></div></article></div>
            <h2 className="hub-section-title">Other helpful official resources</h2><div className="hub-grid">{[{name:"CERT-In",desc:"National incident response agency and security advisories.",url:"https://www.cert-in.org.in/"},{name:"Ministry of Home Affairs",desc:"Government information and cybercrime coordination.",url:"https://www.mha.gov.in/"},{name:"Emergency response",desc:"Call 112 for immediate physical danger or emergencies.",url:"https://112.gov.in/"}].map(x=><article className="hub-card" key={x.name}><h3>{x.name}</h3><p>{x.desc}</p><a className="text-link" href={x.url} target="_blank" rel="noreferrer">Visit official website ↗</a></article>)}</div>
            <div className="attack-intro"><b>Important</b><p>CyberShield AI does not submit complaints on your behalf. Save screenshots, transaction IDs, phone numbers, URLs and messages as evidence. Never share OTPs, PINs or passwords with anyone claiming to help.</p></div>
          </section>}

          {active === "laws" && <section className="page-section">
            <div className="eyebrow">LEGAL AWARENESS / INDIA</div><h1 className="page-title">Cyber Laws in India</h1><p className="lead">A simple overview of key Indian laws and provisions relevant to online safety.</p>
            <div className="hub-grid law-grid">{[{title:"IT Act, 2000 — Section 66C",desc:"Identity theft: fraudulent or dishonest use of another person's electronic signature, password or unique identification feature."},{title:"IT Act, 2000 — Section 66D",desc:"Cheating by personation using a communication device or computer resource."},{title:"IT Act, 2000 — Section 66E",desc:"Violation of privacy by capturing, publishing or transmitting images of a person's private area in the circumstances covered by the section."},{title:"IT Act, 2000 — Sections 67 & 67A",desc:"Provisions addressing publication or transmission of obscene and sexually explicit material in electronic form."},{title:"IT Act, 2000 — Section 70B",desc:"Provides for CERT-In as the national agency for incident response, with functions and powers relating to cyber security incidents."},{title:"Digital Personal Data Protection Act, 2023",desc:"A framework for processing digital personal data and protecting individuals' personal data, subject to the Act and applicable rules/commencement."},{title:"Information Technology Rules, 2021",desc:"Rules covering intermediary due diligence and grievance redressal obligations, as amended."},{title:"Bharatiya Nyaya Sanhita, 2023",desc:"General criminal-law provisions may also apply to online cheating, fraud, intimidation and related offences depending on the facts."}].map((law)=><article className="hub-card law-card" key={law.title}><span className="hub-icon">⚖</span><h3>{law.title}</h3><p>{law.desc}</p></article>)}</div>
            <div className="official-strip"><b>Official references</b><a href="https://www.indiacode.nic.in/" target="_blank" rel="noreferrer">India Code ↗</a><a href="https://www.meity.gov.in/" target="_blank" rel="noreferrer">MeitY ↗</a><a href="https://www.cert-in.org.in/" target="_blank" rel="noreferrer">CERT-In ↗</a></div><p className="hub-disclaimer">For awareness only, not legal advice. Laws, rules and commencement notifications may change; consult the current official text or a qualified legal professional.</p>
          </section>}

          {active === "victim" && <section className="page-section">
            <div className="eyebrow">SUPPORT & RECOVERY / INDIA</div><h1 className="page-title">Victim Help Centre</h1><p className="lead">If you have been targeted, act quickly, preserve evidence and use trusted support channels.</p>
            <div className="victim-layout"><article className="hub-card immediate-card"><h3>Immediate actions</h3><ol><li>Stop communicating with the suspected scammer.</li><li>For financial fraud, call 1930 immediately and contact your bank or payment provider.</li><li>Change exposed passwords from a trusted device and enable multi-factor authentication.</li><li>Save evidence: screenshots, messages, URLs, call details and transaction IDs.</li><li>File a complaint at the official National Cyber Crime Reporting Portal.</li></ol><a className="btn btn-primary" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">Report cybercrime ↗</a></article><div className="victim-types">{[{t:"UPI or bank fraud",d:"Call 1930 immediately, alert your bank/payment app, block affected cards or accounts where appropriate, and keep transaction references."},{t:"Phishing or OTP scam",d:"Do not share further codes. If credentials were entered, change them through the official app/site and secure related accounts."},{t:"Social media account hacked",d:"Use the platform's official account-recovery process, revoke unknown sessions and secure the linked email account."},{t:"Identity theft",d:"Secure affected accounts, alert relevant service providers and preserve proof of impersonation or unauthorised use."},{t:"Cyberbullying or threats",d:"Preserve messages and profile details, block/report the account, and contact police if there is an immediate safety risk."},{t:"Ransomware or malware",d:"Disconnect the affected device from networks if safe to do so, avoid deleting evidence and seek trusted technical assistance."}].map(x=><article className="hub-card" key={x.t}><h3>{x.t}</h3><p>{x.d}</p></article>)}</div></div>
            <div className="resource-banner"><div><small>GOVERNMENT OF INDIA HELPLINE</small><strong>1930</strong><p>National helpline for reporting financial cyber fraud</p></div><a className="btn btn-outline" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">National portal ↗</a></div>
          </section>}

          {active === "awareness" && <section className="page-section"><div className="eyebrow">SECURITY PLAYBOOK</div><h1 className="page-title">Stay safer online.</h1><p className="lead">Small habits make a meaningful difference.</p><div className="attack-intro"><b>Know the playbook</b><p>Cyber attacks often exploit trust, urgency, curiosity or weak account security. Learn the warning signs and the safest response.</p></div><div className="tips-grid">{[["01","Phishing","Fake emails or websites imitate trusted brands to steal logins, payment details or personal data.","Check the sender and domain carefully. Open the official site yourself; never use an unexpected sign-in link."],["02","Smishing & vishing","Scams delivered by SMS or phone call. Attackers may pose as banks, delivery firms, support staff or authorities.","Do not share OTPs or remote-access codes. Hang up and call the organisation using a verified number."],["03","QR phishing (quishing)","A malicious QR code can hide a link to a counterfeit login page, payment request or harmful download.","Preview the decoded URL before opening it. Check the domain and avoid QR codes placed over legitimate ones."],["04","Credential theft & password attacks","Stolen passwords may be reused in credential stuffing; guessing attacks target common or weak passwords.","Use a unique long password for every account, a password manager and multi-factor authentication."],["05","Social engineering & impersonation","An attacker manipulates someone into sending money, revealing secrets or approving an account action.","Pause when a request is urgent or unusual. Verify it through a separate, trusted communication channel."],["06","Malware & ransomware","Malicious files or apps can spy, steal information, encrypt files or disrupt a device.","Install software only from trusted sources, keep devices updated and maintain offline or protected backups."],["07","Fake payment & shopping scams","Fraudulent shops, invoices or payment pages use lookalike domains, fake discounts and pressure tactics.","Check the exact domain, seller reputation and payment recipient. Be wary of irreversible payment methods."],["08","Wi-Fi & session risks","Untrusted networks or stolen browser sessions can expose traffic or allow account access.","Use HTTPS, keep sharing disabled on public networks, sign out of shared devices and protect your device."],["09","Protect verification codes","OTP, recovery-code and MFA-push scams trick users into handing over the final key to an account.","Never read out a code or approve a login you did not initiate. Deny unexpected MFA prompts."],["10","Everyday safety checklist","Security improves when small habits become routine.","Update software, enable MFA, back up important files, use unique passwords and report suspicious messages."]].map(([n,t,d,a]) => <article className="tip-card attack-card" key={n}><span>{n}</span><div><h3>{t}</h3><p>{d}</p><small><b>What to do:</b> {a}</small></div></article>)}</div></section>}
          <footer className="footer"><span>© 2026 CyberShield AI</span><span>SECURITY IS A PRACTICE, NOT A PROMISE.</span></footer>
        </div>
      </main>
      {showAuth && <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setShowAuth(false); }}><div className="auth-modal"><button className="modal-close" onClick={() => setShowAuth(false)}>×</button><div className="eyebrow">CYBERSHIELD ACCOUNT</div><Auth onSuccess={() => setShowAuth(false)} /></div></div>}
    </div>
  );
}

function Metric({ label, value, icon, hint }) {
  return <article className="metric-card"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{hint}</small></article>;
}
function ToolCard({ icon, tag, title, desc, onClick }) {
  return <button className="tool-card" onClick={onClick}><span className="tool-icon">{icon}</span><span className="tool-tag">{tag}</span><b>{title}</b><p>{desc}</p><span className="tool-arrow">Explore tool ↗</span></button>;
}
function ScannerPage({ eyebrow, title, description, icon, children }) {
  return <section className="page-section scanner-page"><div className="eyebrow">{eyebrow}</div><div className="scanner-heading"><div><h1 className="page-title">{title}</h1><p className="lead">{description}</p></div><span className="scanner-icon">{icon}</span></div><div className="scanner-card">{children}</div></section>;
}
function ResultPanel({ result }) {
  if (!result) return null;
  if (result.error) return <div className="result-panel error"><b>Scan could not be completed</b><p>{result.error}</p></div>;
  const verdict = result.verdict || "UNKNOWN";
  return <div className={`result-panel ${riskTone(verdict)}`}><div className="result-top"><div><small>SCAN RESULT</small><h3>{verdict}</h3></div><RiskBadge verdict={verdict} /></div><div className="risk-meter"><div><span>Risk score</span><b>{result.risk_score ?? "—"}<small>/100</small></b></div><div className="strength-track"><span style={{ width: `${Math.max(0, Math.min(100, Number(result.risk_score || 0)))}%` }} /></div></div>{result.google_safe_browsing && <p className="result-detail">Google Safe Browsing: {result.google_safe_browsing.replaceAll("_", " ")}</p>}{(result.reasons || result.matched_indicators || result.explanations || result.risk_factors || result.indicators || result.method) && <div className="explanation-block"><h4>Why this result was given</h4>{result.method && <p className="method-note">Detection method: {result.method}</p>}<ul>{(Array.isArray(result.reasons || result.matched_indicators || result.explanations || result.risk_factors || result.indicators) ? (result.reasons || result.matched_indicators || result.explanations || result.risk_factors || result.indicators) : [result.reasons || result.matched_indicators || result.explanations || result.risk_factors || result.indicators]).map((item, index) => <li key={index}>{typeof item === "string" ? (result.matched_indicators ? `Matched message indicator: “${item}” — this wording is commonly used in credential, prize or urgency scams.` : item) : item.description || item.reason || JSON.stringify(item)}</li>)}</ul>{result.kind === "message" && <p className="method-note">A keyword match is a clue, not proof of fraud. Review the sender, context and destination independently.</p>}</div>}<p className="result-disclaimer">Automated assessment only. A SAFE result does not guarantee that a website or message is harmless.</p></div>;
}

export default App;
