import { useState } from "react";
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
} from "firebase/auth";
import { auth } from "./firebase";

function Auth({ onSuccess }) {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage("");
    if (password.length < 6) {
      setMessage("Use a password with at least 6 characters.");
      return;
    }
    setBusy(true);
    try {
      if (isRegister) {
        await createUserWithEmailAndPassword(auth, email.trim(), password);
      } else {
        await signInWithEmailAndPassword(auth, email.trim(), password);
      }
      onSuccess?.();
    } catch (error) {
      const messages = {
        "auth/email-already-in-use": "An account already exists for this email. Try signing in.",
        "auth/invalid-credential": "Email or password is incorrect.",
        "auth/weak-password": "Choose a stronger password (at least 6 characters).",
        "auth/invalid-email": "Enter a valid email address.",
        "auth/too-many-requests": "Too many attempts. Please wait and try again.",
        "auth/network-request-failed": "Network error. Check your internet connection.",
      };
      setMessage(messages[error.code] || error.message || "Authentication failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-content">
      <div className="auth-symbol">✦</div>
      <h2>{isRegister ? "Create your account" : "Welcome back"}</h2>
      <p>{isRegister ? "Save your scans and keep your security activity in one place." : "Sign in to access your private scan history."}</p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="auth-email">EMAIL ADDRESS</label>
        <input id="auth-email" type="email" autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label htmlFor="auth-password">PASSWORD</label>
        <input id="auth-password" type="password" autoComplete={isRegister ? "new-password" : "current-password"} placeholder="At least 6 characters" value={password} onChange={(e) => setPassword(e.target.value)} minLength={6} required />
        {message && <div className="auth-error" role="alert">{message}</div>}
        <button className="btn btn-primary auth-submit" type="submit" disabled={busy}>{busy ? "Please wait…" : isRegister ? "Create account →" : "Sign in →"}</button>
      </form>
      <button className="auth-switch" type="button" onClick={() => { setIsRegister(!isRegister); setMessage(""); }}>{isRegister ? "Already registered? Sign in" : "New to CyberShield? Create an account"}</button>
      <small className="auth-footnote">Your account is secured with Firebase Authentication.</small>
    </div>
  );
}
export default Auth;
