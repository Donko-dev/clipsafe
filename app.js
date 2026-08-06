/* =========================================================================
   ClipSafe — app.js
   Moteur applicatif de la page publique. Tout le contenu affiché provient
   de data.json : rien n'est codé en dur. Le contenu collé par l'utilisateur
   n'est jamais traduit — seule l'interface (titres, héros, sous-titres,
   pied de page) change avec la langue choisie.
   ========================================================================= */

"use strict";

/* -------------------------------------------------------------------------
   0. Protections client basiques (dissuasives, pas absolues)
   ------------------------------------------------------------------------- */
document.addEventListener("contextmenu", (e) => e.preventDefault());
document.addEventListener("keydown", (e) => {
  const blocked =
    e.key === "F12" ||
    (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key.toUpperCase())) ||
    (e.ctrlKey && e.key.toUpperCase() === "U");
  if (blocked) e.preventDefault();
});

/* -------------------------------------------------------------------------
   1. Cryptographie (Web Crypto API)
   ------------------------------------------------------------------------- */
const CryptoBox = {
  KEY_STORAGE: "cs_vault_key",

  async _getKey() {
    const stored = localStorage.getItem(this.KEY_STORAGE);
    if (stored) {
      const raw = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
      return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
    }
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const exported = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    localStorage.setItem(this.KEY_STORAGE, btoa(String.fromCharCode(...exported)));
    return key;
  },

  async encrypt(plainText) {
    const key = await this._getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded));
    const payload = new Uint8Array(iv.length + cipher.length);
    payload.set(iv, 0);
    payload.set(cipher, iv.length);
    return btoa(String.fromCharCode(...payload));
  },

  async decrypt(b64) {
    const key = await this._getKey();
    const payload = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const iv = payload.slice(0, 12);
    const cipher = payload.slice(12);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    return new TextDecoder().decode(plain);
  },

  async sha256Hex(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  },
};

/* -------------------------------------------------------------------------
   2. Verrou Premium (dissuasif, pas une preuve cryptographique de paiement —
      cela nécessiterait un serveur, ce que ClipSafe n'a pas par conception)
   ------------------------------------------------------------------------- */
const PremiumLock = {
  FLAG_KEY: "cs_px",
  SIG_KEY: "cs_px_sig",
  SALT_KEY: "cs_px_salt",
  KEYHASH_KEY: "cs_px_keyhash",
  EXPIRES_KEY: "cs_px_expires",

  async _salt() {
    let salt = localStorage.getItem(this.SALT_KEY);
    if (!salt) {
      salt = crypto.getRandomValues(new Uint8Array(16)).join("-");
      localStorage.setItem(this.SALT_KEY, salt);
    }
    return salt;
  },

  async isPremium() {
    const flag = localStorage.getItem(this.FLAG_KEY);
    const sig = localStorage.getItem(this.SIG_KEY);
    const keyHash = localStorage.getItem(this.KEYHASH_KEY) || "";
    const expires = localStorage.getItem(this.EXPIRES_KEY) || "";
    if (!flag || !sig || flag !== "granted") return false;
    const salt = await this._salt();
    const expected = await CryptoBox.sha256Hex(salt + ":granted:" + keyHash + ":" + expires);
    if (expected !== sig) return false;
    if (expires && Date.now() > Number(expires)) {
      this.revoke();
      return false;
    }
    return true;
  },

  /** durationDays: 0/falsy = à vie. Retourne le timestamp d'expiration (ou null si à vie). */
  async grant(keyHash, durationDays) {
    const salt = await this._salt();
    const expires = durationDays && durationDays > 0 ? String(Date.now() + durationDays * 86400000) : "";
    const sig = await CryptoBox.sha256Hex(salt + ":granted:" + keyHash + ":" + expires);
    localStorage.setItem(this.FLAG_KEY, "granted");
    localStorage.setItem(this.SIG_KEY, sig);
    localStorage.setItem(this.KEYHASH_KEY, keyHash);
    localStorage.setItem(this.EXPIRES_KEY, expires);
    return expires ? Number(expires) : null;
  },

  revoke() {
    localStorage.removeItem(this.FLAG_KEY);
    localStorage.removeItem(this.SIG_KEY);
    localStorage.removeItem(this.KEYHASH_KEY);
    localStorage.removeItem(this.EXPIRES_KEY);
  },

  async getExpiresAt() {
    const expires = localStorage.getItem(this.EXPIRES_KEY);
    return expires ? Number(expires) : null;
  },
};

/* -------------------------------------------------------------------------
   3. Essai gratuit de 7 jours (configurable via data.json > premium.trialDays)
   Le compteur démarre au premier élément ajouté, jamais avant.
   ------------------------------------------------------------------------- */
const TrialLock = {
  START_KEY: "cs_trial_start",
  SIG_KEY: "cs_trial_sig",

  async start() {
    const salt = await PremiumLock._salt();
    const now = String(Date.now());
    const sig = await CryptoBox.sha256Hex(salt + ":trial:" + now);
    localStorage.setItem(this.START_KEY, now);
    localStorage.setItem(this.SIG_KEY, sig);
    return Number(now);
  },

  async getStart() {
    const start = localStorage.getItem(this.START_KEY);
    const sig = localStorage.getItem(this.SIG_KEY);
    if (!start || !sig) return null;
    const salt = await PremiumLock._salt();
    const expected = await CryptoBox.sha256Hex(salt + ":trial:" + start);
    if (expected !== sig) return null;
    return Number(start);
  },
};

/* -------------------------------------------------------------------------
   4. Sanitisation (anti-XSS)
   ------------------------------------------------------------------------- */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}
function escapeAttr(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/* -------------------------------------------------------------------------
   5. Détection automatique du type de contenu (100% locale, aucune librairie)
   ------------------------------------------------------------------------- */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const URL_RE = /^(https?:\/\/|www\.)\S+$/i;
const PHONE_RE = /^[+()0-9\s.-]{6,20}$/;
const PORTFOLIO_DOMAINS = /github\.io|behance\.net|dribbble\.com|notion\.site|vercel\.app|netlify\.app/i;

const CV_KEYWORDS = [
  "curriculum vitae", "expérience professionnelle", "compétences", "formation académique",
  "objectif professionnel", "profil professionnel", "références professionnelles",
  "resume", "professional summary", "work history", "education", "skills",
  "lebenslauf", "berufserfahrung", "fähigkeiten", "ausbildung",
  "currículum", "experiencia laboral", "habilidades", "educación",
];
const PORTFOLIO_KEYWORDS = ["portfolio", "portefeuille de projets", "projets", "projects", "case study", "réalisations"];

function countHits(lowerText, keywords) {
  return keywords.reduce((n, k) => n + (lowerText.includes(k) ? 1 : 0), 0);
}

function detectCodeLang(text) {
  const t = text;
  if (/<\?php/i.test(t)) return "php";
  if (/<!doctype html/i.test(t) || /<html[\s>]/i.test(t) || (/<\/[a-z][\w-]*>/i.test(t) && /<(div|span|body|head|p|a|img|section|header|footer|button|ul|li)\b/i.test(t))) return "html";
  const trimmed = t.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "json";
    } catch {
      /* not valid JSON, keep checking other languages */
    }
  }
  if (/<\?xml/i.test(t)) return "xml";
  if (/^#{1,6}\s.+/m.test(t) && (/```/.test(t) || /\[.+\]\(.+\)/.test(t) || /^\s*[-*]\s+\S/m.test(t))) return "markdown";
  if (/#include\s*<\w+>/.test(t) && (/std::/.test(t) || /\bcout\s*<</.test(t) || /\bclass\s+\w+/.test(t))) return "cpp";
  if (/#include\s*<\w+(\.h)?>/.test(t) && /\bint\s+main\s*\(/.test(t) && !/std::/.test(t)) return "c";
  if (/\bpublic\s+class\s+\w+/.test(t) || /\bSystem\.out\.println/.test(t)) return "java";
  if (/\busing\s+System;/.test(t) || (/\bnamespace\s+\w+/.test(t) && /\bclass\s+\w+/.test(t)) || /\bConsole\.WriteLine/.test(t)) return "csharp";
  if (/^\s*def\s+\w+\(.*\)\s*:/m.test(t) || /\bself\./.test(t) || (/^\s*import\s+\w+/m.test(t) && /:\s*$/m.test(t))) return "python";
  if (/\bSELECT\b[\s\S]{0,300}\bFROM\b/i.test(t) || /\bINSERT\s+INTO\b/i.test(t) || /\bCREATE\s+TABLE\b/i.test(t)) return "sql";
  if (/^#!\s*\/bin\/(bash|sh)/.test(t) || (/\becho\s+["'$]/.test(t) && /\$\{?\w+\}?/.test(t))) return "bash";
  if (/:\s*(string|number|boolean|any|void)\b/.test(t) && (/\binterface\s+\w+/.test(t) || /:\s*\(.*\)\s*=>/.test(t))) return "typescript";
  if (/\bfunction\s*\w*\s*\(/.test(t) || /=>\s*\{/.test(t) || /\bconst\s+\w+\s*=/.test(t) || /\bconsole\.log\(/.test(t)) return "javascript";
  if (/\bpackage\s+main\b/.test(t) && /\bfunc\s+main\s*\(/.test(t)) return "go";
  if (/^\s*def\s+\w+/m.test(t) && /\bend\b/.test(t) && /\bputs\s+/.test(t)) return "ruby";
  if (/[.#]?[\w-]+\s*\{[^{}]*:[^{}]*;[^{}]*\}/.test(t) && !/\bfunction\b/.test(t) && !/<\?php/.test(t)) return "css";
  const density = (t.match(/[{}();=<>]/g) || []).length / Math.max(t.length, 1);
  if (density > 0.04 && /\n/.test(t) && t.trim().length > 20) return "other";
  return null;
}

function detectCategory(text) {
  const trimmed = text.trim();
  if (EMAIL_RE.test(trimmed)) return { category: "emails" };
  if (URL_RE.test(trimmed)) {
    return { category: PORTFOLIO_DOMAINS.test(trimmed) ? "portfolio" : "links" };
  }
  if (PHONE_RE.test(trimmed) && /\d{4,}/.test(trimmed)) return { category: "numbers" };

  const lower = trimmed.toLowerCase();
  if (trimmed.length > 200 && countHits(lower, CV_KEYWORDS) >= 2) return { category: "cv" };

  const urlMatches = trimmed.match(/https?:\/\/\S+/g) || [];
  if (urlMatches.length >= 2 && countHits(lower, PORTFOLIO_KEYWORDS) >= 1) return { category: "portfolio" };

  const codeLang = detectCodeLang(trimmed);
  if (codeLang) return { category: "code", codeLang };

  return { category: "texts" };
}

function detectFileKind(file) {
  const type = (file.type || "").toLowerCase();
  const name = (file.name || "").toLowerCase();
  if (type === "application/pdf" || name.endsWith(".pdf")) return "pdf";
  if (type.includes("wordprocessingml") || type === "application/msword" || name.endsWith(".doc") || name.endsWith(".docx")) return "word";
  if (type.includes("spreadsheetml") || type === "application/vnd.ms-excel" || name.endsWith(".xls") || name.endsWith(".xlsx")) return "excel";
  if (type.includes("presentationml") || type === "application/vnd.ms-powerpoint" || name.endsWith(".ppt") || name.endsWith(".pptx")) return "powerpoint";
  return "other";
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}
function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}
async function readClipboardImage() {
  if (!navigator.clipboard || !navigator.clipboard.read) throw new Error("unsupported");
  const items = await navigator.clipboard.read();
  for (const item of items) {
    const imgType = item.types.find((t) => t.startsWith("image/"));
    if (imgType) return item.getType(imgType);
  }
  throw new Error("no-image");
}

/* -------------------------------------------------------------------------
   6. Icônes SVG inline
   ------------------------------------------------------------------------- */
const ICONS = {
  whatsapp: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M17.5 14.4c-.3-.1-1.7-.9-2-1-.3-.1-.5-.1-.7.1-.2.3-.8 1-.9 1.2-.2.2-.3.2-.6.1-.3-.1-1.3-.5-2.4-1.5-.9-.8-1.5-1.8-1.6-2.1-.2-.3 0-.5.1-.6.1-.1.3-.3.4-.5.1-.1.2-.3.3-.5.1-.2 0-.4 0-.5-.1-.1-.7-1.6-.9-2.2-.2-.6-.5-.5-.7-.5h-.6c-.2 0-.5.1-.8.4-.3.3-1 1-1 2.4s1.1 2.8 1.2 3c.1.2 2.2 3.3 5.3 4.6.7.3 1.3.5 1.8.7.7.2 1.4.2 1.9.1.6-.1 1.7-.7 2-1.4.2-.7.2-1.3.2-1.4-.1-.2-.3-.2-.6-.3z"/><path fill="currentColor" d="M12 2C6.5 2 2 6.5 2 12c0 1.9.5 3.6 1.4 5.1L2 22l5-1.3c1.4.8 3.1 1.3 4.9 1.3 5.5 0 10-4.5 10-10S17.5 2 12 2zm0 18.2c-1.6 0-3.1-.4-4.4-1.2l-.3-.2-3 .8.8-2.9-.2-.3C4.2 14.9 3.8 13.5 3.8 12c0-4.5 3.7-8.2 8.2-8.2s8.2 3.7 8.2 8.2-3.7 8.2-8.2 8.2z"/></svg>',
  shop: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M4 4h16l-1.5 9h-13z" opacity=".25"/><path fill="currentColor" d="M6 22a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zm12 0a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM3 3h2l2.4 12.2a2 2 0 0 0 2 1.6h7.2a2 2 0 0 0 2-1.6L21 7H6"/></svg>',
  mail: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm1.4 2L12 12.5 19.6 7H4.4zM20 8.4l-7.4 5.4a1 1 0 0 1-1.2 0L4 8.4V18h16V8.4z"/></svg>',
  text: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M4 4h16v2H4zm0 6h16v2H4zm0 6h10v2H4z"/></svg>',
  link: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M10.6 13.4a1 1 0 0 1 0-1.4l3-3a1 1 0 1 1 1.4 1.4l-3 3a1 1 0 0 1-1.4 0zM8.5 15.5l-1 1a2.5 2.5 0 0 1-3.5-3.5l3-3a2.5 2.5 0 0 1 3.5 0 1 1 0 1 1-1.4 1.4.5.5 0 0 0-.7 0l-3 3a.5.5 0 0 0 .7.7l1-1a1 1 0 1 1 1.4 1.4zm7-7 1-1a2.5 2.5 0 0 1 3.5 3.5l-3 3a2.5 2.5 0 0 1-3.5 0 1 1 0 1 1 1.4-1.4.5.5 0 0 0 .7 0l3-3a.5.5 0 0 0-.7-.7l-1 1a1 1 0 1 1-1.4-1.4z"/></svg>',
  hash: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9.5 3l-1 6H4v2h4.2l-.6 4H3v2h4.3l-1 5h2l1-5h4l-1 5h2l1-5H20v-2h-4.2l.6-4H21V9h-4.3l1-6h-2l-1 6h-4l1-6h-2zm.9 8h4l-.6 4h-4l.6-4z"/></svg>',
  email: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm1.4 2L12 12.5 19.6 7H4.4zM20 8.4l-7.4 5.4a1 1 0 0 1-1.2 0L4 8.4V18h16V8.4z"/></svg>',
  code: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6zm5.2 0L19.2 12l-4.6-4.6L16 6l6 6-6 6z"/></svg>',
  cv: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm4 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-3 8h6c0-1.7-1.3-3-3-3s-3 1.3-3 3zm9-6h5v1.5h-5V10zm0 3h5v1.5h-5V13z"/></svg>',
  portfolio: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9 3h6a1 1 0 0 1 1 1v2h4a2 2 0 0 1 2 2v3H2V8a2 2 0 0 1 2-2h4V4a1 1 0 0 1 1-1zm1 3h4V5h-4v1zM2 12h20v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6zm8 1v2h4v-2h-4z"/></svg>',
  image: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm1 2v9.5l4-4 3 3 5-5 4 4V6H5zm3 2a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/></svg>',
  document: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M6 2h9l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm8 1.5V8h4.5L14 3.5zM7 12h10v1.5H7V12zm0 3.5h10V17H7v-1.5zM7 8.5h5V10H7V8.5z"/></svg>',
  copy: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9 9h2v9H9zm4 0h2v9h-2z"/><path fill="currentColor" d="M6 7h12l-1 14H7L6 7zm3-3h6l1 2H8l1-2z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3H9V6a3 3 0 0 1 3-3z"/></svg>',
  pin: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M14.7 2.3a1 1 0 0 0-1.4 0L11 4.6a3 3 0 0 0-3.5.6L6.4 6.3a1 1 0 0 0 0 1.4l2.1 2.1-4.2 4.2a1 1 0 0 0 0 1.4l.7.7a1 1 0 0 0 1.4 0l4.2-4.2 2.1 2.1a1 1 0 0 0 1.4 0l1.1-1.1a3 3 0 0 0 .6-3.5l2.3-2.3a1 1 0 0 0 0-1.4l-3.5-3.5z"/></svg>',
  star: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M12 2l2.9 6.6 7.1.6-5.4 4.7 1.7 7-6.3-3.8L5.7 21l1.7-7-5.4-4.7 7.1-.6L12 2z"/></svg>',
  share: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M18 16.1a3 3 0 0 0-2.1.9l-6.1-3.5a3 3 0 0 0 0-1L15.9 9a3 3 0 1 0-.8-1.7l-6.1 3.5a3 3 0 1 0 0 4.4l6.1 3.6a3 3 0 1 0 2.9-2.7z"/></svg>',
  edit: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M3 17.25V21h3.75L17.8 9.94l-3.75-3.75L3 17.25zM20.7 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>',
  close: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M6.4 5L5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4 17.6 5 12 10.6z"/></svg>',
  upload: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M12 3l5 5h-3v6h-4V8H7l5-5zM5 19v-4h2v4h10v-4h2v4a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2z"/></svg>',
  wand: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M7.5 2l.9 2 2 .9-2 .9-.9 2-.9-2-2-.9 2-.9.9-2zM17 3l1.2 2.6L21 7l-2.8 1.4L17 11l-1.2-2.6L13 7l2.8-1.4L17 3zM6 13l1 2.2L9.2 16 7 17 6 19.2 5 17l-2.2-1L5 15.2 6 13zM14.5 10l7.5 7.5-4 4L10.5 14l4-4z"/></svg>',
  telegram: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M2 11.6L21 3l-3.4 18-5.8-4.5-2.8 2.7-.5-4.3L2 11.6z"/></svg>',
  x: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M3 3l7.5 9.5L3.3 21H6l5.8-6.4L16.5 21H21l-8-10.2L20.4 3h-2.7l-5.3 5.8L7.5 3H3z"/></svg>',
  sms: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M4 4h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8l-4 4V6a2 2 0 0 1 2-2z"/></svg>',
};

const CODE_LANG_LABELS = {
  html: "HTML", css: "CSS", json: "JSON", xml: "XML", markdown: "Markdown",
  python: "Python", javascript: "JavaScript", typescript: "TypeScript", php: "PHP",
  c: "C", cpp: "C++", java: "Java", csharp: "C#", sql: "SQL", bash: "Bash/Shell",
  go: "Go", ruby: "Ruby",
};
const FILE_KIND_LABELS = { pdf: "PDF", word: "Word", excel: "Excel", powerpoint: "PowerPoint" };
const LOCALE_MAP = { fr: "fr-FR", en: "en-US", de: "de-DE", es: "es-ES", zh: "zh-CN", ar: "ar-EG", ru: "ru-RU" };
const LANG_META = {
  fr: { flag: "🇫🇷", name: "Français" },
  en: { flag: "🇬🇧", name: "English" },
  de: { flag: "🇩🇪", name: "Deutsch" },
  es: { flag: "🇪🇸", name: "Español" },
  zh: { flag: "🇨🇳", name: "中文" },
  ar: { flag: "🇸🇦", name: "العربية" },
  ru: { flag: "🇷🇺", name: "Русский" },
};

/* -------------------------------------------------------------------------
   7. Application principale
   ------------------------------------------------------------------------- */
const ClipSafeApp = {
  data: null,
  vaultKey: "cs_vault_items",
  LANG_KEY: "cs_lang",
  MODE_KEY: "cs_theme_mode",
  filters: { search: "", category: "all", codeLang: "all", onlyFavorites: false, onlyPinned: false },
  detailEditing: false,
  licenseFromExpiry: false,

  async init() {
    this.root = document.getElementById("app-root");
    try {
      const res = await fetch("data.json", { cache: "no-store" });
      this.data = await res.json();
    } catch {
      this.root.innerHTML = `<p class="cs-error">Impossible de charger la configuration (data.json).</p>`;
      return;
    }
    this.setupOverlay();
    this.applyTheme();
    this.render();
    this.registerServiceWorker();
  },

  setupOverlay() {
    this.overlay = document.createElement("div");
    this.overlay.className = "cs-overlay";
    this.overlay.hidden = true;
    this.overlay.addEventListener("click", (e) => {
      if (e.target === this.overlay) this.closeOverlay();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !this.overlay.hidden) this.closeOverlay();
    });
    document.body.appendChild(this.overlay);
  },
  showOverlay() {
    this.overlay.hidden = false;
    document.body.style.overflow = "hidden";
  },
  closeOverlay() {
    this.overlay.hidden = true;
    this.overlay.innerHTML = "";
    document.body.style.overflow = "";
    this.detailEditing = false;
  },

  /* ---- Langue ---- */
  getLang() {
    const saved = localStorage.getItem(this.LANG_KEY);
    const supported = this.data.languages || ["fr"];
    if (saved && supported.includes(saved)) return saved;
    const browserLang = (navigator.language || "fr").slice(0, 2).toLowerCase();
    if (supported.includes(browserLang)) return browserLang;
    return this.data.defaultLanguage || "fr";
  },
  setLang(lang) {
    localStorage.setItem(this.LANG_KEY, lang);
    this.render();
  },
  t(path) {
    const lang = this.getLang();
    const dict = this.data.i18n || {};
    const fallbackLang = this.data.defaultLanguage || "fr";
    const dig = (obj, p) => p.split(".").reduce((acc, k) => (acc && acc[k] !== undefined ? acc[k] : undefined), obj);
    return dig(dict[lang], path) ?? dig(dict[fallbackLang], path) ?? path;
  },

  /* ---- Thème clair/sombre ---- */
  getMode() {
    return localStorage.getItem(this.MODE_KEY) || this.data.theme.defaultMode || "dark";
  },
  setMode(mode) {
    localStorage.setItem(this.MODE_KEY, mode);
    this.applyTheme();
    const toggle = document.getElementById("cs-theme-toggle");
    if (toggle) toggle.textContent = mode === "dark" ? "☀️" : "🌙";
  },
  applyTheme() {
    const { colorModes, fonts, radius } = this.data.theme;
    const colors = colorModes[this.getMode()] || colorModes.dark;
    const root = document.documentElement.style;
    Object.entries(colors).forEach(([k, v]) => root.setProperty(`--cs-${k}`, v));
    root.setProperty("--cs-font-display", fonts.display);
    root.setProperty("--cs-font-body", fonts.body);
    root.setProperty("--cs-font-mono", fonts.mono);
    root.setProperty("--cs-radius", radius);
    document.title = this.data.app.name + " — " + this.t("tagline");
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", colors.bg);
    const favicon = document.getElementById("cs-favicon");
    if (favicon && this.data.branding?.faviconSvg) {
      favicon.href = "data:image/svg+xml," + encodeURIComponent(this.data.branding.faviconSvg);
    }
  },

  /* ---- Rendu principal ---- */
  render() {
    const lang = this.getLang();
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    this.root.innerHTML = "";

    const header = document.createElement("header");
    header.className = "cs-topbar";
    const currentMode = this.getMode();
    const langOptions = (this.data.languages || ["fr"])
      .map((l) => {
        const meta = LANG_META[l] || { flag: "", name: l.toUpperCase() };
        return `<option value="${l}" ${l === lang ? "selected" : ""}>${meta.flag} ${escapeHtml(meta.name)}</option>`;
      })
      .join("");
    header.innerHTML = `
      <div class="cs-logo">${this.data.branding?.logoSvg || ""}</div>
      <span class="cs-appname">${escapeHtml(this.data.app.name)}</span>
      <select id="cs-lang-select" class="cs-lang-select" title="${escapeAttr(this.t("ui.langLabel"))}">${langOptions}</select>
      <button id="cs-theme-toggle" class="cs-theme-toggle" type="button" title="Thème">${currentMode === "dark" ? "☀️" : "🌙"}</button>
    `;
    header.querySelector("#cs-theme-toggle").addEventListener("click", () => {
      this.setMode(this.getMode() === "dark" ? "light" : "dark");
    });
    header.querySelector("#cs-lang-select").addEventListener("change", (e) => this.setLang(e.target.value));
    this.root.appendChild(header);

    const enabledSections = this.data.sections.filter((s) => s.enabled).sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    enabledSections.forEach((section) => {
      const el = this.renderSection(section);
      if (el) this.root.appendChild(el);
    });

    this.root.appendChild(this.renderFooter());
  },

  renderSection(section) {
    const wrap = document.createElement("section");
    wrap.className = `cs-section cs-section--${section.type}`;
    wrap.id = `section-${section.id}`;

    const title = this.t(`sections.${section.id}.title`);
    const subtitle = this.t(`sections.${section.id}.subtitle`);

    const titleTag = document.createElement("h2");
    titleTag.className = "cs-section-title";
    if (section.style?.bold) titleTag.style.fontWeight = "700";
    if (section.style?.italic) titleTag.style.fontStyle = "italic";
    if (section.style?.underline) titleTag.style.textDecoration = "underline";
    titleTag.textContent = title;
    wrap.appendChild(titleTag);

    if (subtitle) {
      const sub = document.createElement("p");
      sub.className = "cs-section-subtitle";
      sub.textContent = subtitle;
      wrap.appendChild(sub);
    }

    const body = document.createElement("div");
    body.className = "cs-section-body";
    if (section.type === "capture") body.appendChild(this.buildCapture());
    if (section.type === "vault") body.appendChild(this.buildVaultList());
    if (section.type === "premium") body.appendChild(this.buildPremiumBlock());
    wrap.appendChild(body);
    return wrap;
  },

  /* ---- Capture ---- */
  buildCapture() {
    const box = document.createElement("div");
    box.className = "cs-capture";
    box.innerHTML = `
      <textarea id="cs-input" class="cs-textarea" rows="3" placeholder="${escapeAttr(this.t("ui.placeholderCapture"))}"></textarea>
      <div class="cs-capture-actions">
        <button id="cs-paste-btn" class="cs-btn cs-btn--ghost" type="button">${escapeHtml(this.t("ui.pasteBtn"))}</button>
        <button id="cs-paste-image-btn" class="cs-btn cs-btn--ghost" type="button">${ICONS.image}${escapeHtml(this.t("ui.pasteImageBtn"))}</button>
        <button id="cs-import-doc-btn" class="cs-btn cs-btn--ghost" type="button">${ICONS.upload}${escapeHtml(this.t("ui.importDocBtn"))}</button>
        <button id="cs-smart-paste-btn" class="cs-btn cs-btn--ghost" type="button">${ICONS.wand}${escapeHtml(this.t("ui.smartPasteBtn"))}</button>
      </div>
      <input type="file" id="cs-doc-input" hidden accept="*/*" />
      <button id="cs-save-btn" class="cs-btn cs-btn--primary" type="button" style="width:100%;margin-top:0.6rem;">${escapeHtml(this.t("ui.addBtn"))}</button>
    `;

    box.querySelector("#cs-paste-btn").addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        box.querySelector("#cs-input").value = text;
      } catch {
        this.toast(this.t("ui.clipboardDenied"));
      }
    });

    box.querySelector("#cs-paste-image-btn").addEventListener("click", async () => {
      try {
        const blob = await readClipboardImage();
        await this.addImageFromBlob(blob);
      } catch {
        this.toast(this.t("ui.imageDocPasteError"));
      }
    });

    box.querySelector("#cs-import-doc-btn").addEventListener("click", () => box.querySelector("#cs-doc-input").click());
    box.querySelector("#cs-doc-input").addEventListener("change", async (e) => {
      const file = e.target.files[0];
      e.target.value = "";
      if (!file) return;
      await this.addDocumentFromFile(file);
    });

    box.querySelector("#cs-smart-paste-btn").addEventListener("click", () => this.smartPaste(box));

    box.querySelector("#cs-save-btn").addEventListener("click", async () => {
      const input = box.querySelector("#cs-input");
      const value = input.value.trim();
      if (!value) return;
      const added = await this.addItem(value);
      if (added) {
        input.value = "";
        this.refreshVault();
      }
    });

    return box;
  },

  async smartPaste(box) {
    if (navigator.clipboard && navigator.clipboard.read) {
      try {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imgType = item.types.find((t) => t.startsWith("image/"));
          if (imgType) {
            const blob = await item.getType(imgType);
            await this.addImageFromBlob(blob);
            return;
          }
        }
      } catch {
        /* fall through to plain text */
      }
    }
    try {
      const text = await navigator.clipboard.readText();
      if (text) box.querySelector("#cs-input").value = text;
    } catch {
      this.toast(this.t("ui.clipboardDenied"));
    }
  },

  /* ---- Essai / Premium : contrôle avant tout ajout ---- */
  async canAddItem() {
    const isPremium = await PremiumLock.isPremium();
    if (isPremium) return true;
    const trialDays = this.data.premium.trialDays ?? 7;
    let start = await TrialLock.getStart();
    if (!start) {
      await TrialLock.start();
      return true;
    }
    const days = Math.floor((Date.now() - start) / 86400000);
    if (days < trialDays) return true;
    await this.openLicenseModal(true);
    return false;
  },

  /* ---- Stockage chiffré ---- */
  async getItems() {
    const raw = localStorage.getItem(this.vaultKey);
    if (!raw) return [];
    try {
      return JSON.parse(await CryptoBox.decrypt(raw));
    } catch {
      return [];
    }
  },
  async saveItems(items) {
    localStorage.setItem(this.vaultKey, await CryptoBox.encrypt(JSON.stringify(items)));
  },

  async addItem(text) {
    if (!(await this.canAddItem())) return false;
    const { category, codeLang } = detectCategory(text);
    const items = await this.getItems();
    items.unshift({
      id: crypto.randomUUID(),
      category,
      codeLang: codeLang || undefined,
      text,
      favorite: false,
      pinned: false,
      createdAt: new Date().toISOString(),
    });
    await this.saveItems(items);
    this.toast(this.t("ui.itemAddedToast"));
    return true;
  },

  async addImageFromBlob(blob) {
    if (!(await this.canAddItem())) return;
    const dataUrl = await blobToDataUrl(blob);
    const ext = blob.type && blob.type.split("/")[1] ? blob.type.split("/")[1] : "png";
    const items = await this.getItems();
    items.unshift({
      id: crypto.randomUUID(),
      category: "images",
      dataUrl,
      mime: blob.type || "image/png",
      fileName: "image-" + Date.now() + "." + ext,
      favorite: false,
      pinned: false,
      createdAt: new Date().toISOString(),
    });
    await this.saveItems(items);
    this.refreshVault();
    this.toast(this.t("ui.itemAddedToast"));
  },

  async addDocumentFromFile(file) {
    if (!(await this.canAddItem())) return;
    const dataUrl = await fileToDataUrl(file);
    const items = await this.getItems();
    if ((file.type || "").startsWith("image/")) {
      items.unshift({
        id: crypto.randomUUID(), category: "images", dataUrl, mime: file.type,
        fileName: file.name, favorite: false, pinned: false, createdAt: new Date().toISOString(),
      });
    } else {
      items.unshift({
        id: crypto.randomUUID(), category: "documents", fileKind: detectFileKind(file), dataUrl,
        mime: file.type || "application/octet-stream", fileName: file.name,
        favorite: false, pinned: false, createdAt: new Date().toISOString(),
      });
    }
    await this.saveItems(items);
    this.refreshVault();
    this.toast(this.t("ui.documentImportedToast"));
  },

  async deleteItem(id) {
    const items = await this.getItems();
    await this.saveItems(items.filter((i) => i.id !== id));
    this.refreshVault();
  },

  async updateItem(id, patch) {
    const items = await this.getItems();
    const idx = items.findIndex((i) => i.id === id);
    if (idx === -1) return;
    items[idx] = { ...items[idx], ...patch, updatedAt: new Date().toISOString() };
    await this.saveItems(items);
    this.refreshVault();
  },
  async toggleFavorite(id) {
    const item = (await this.getItems()).find((i) => i.id === id);
    if (item) await this.updateItem(id, { favorite: !item.favorite });
  },
  async togglePinned(id) {
    const item = (await this.getItems()).find((i) => i.id === id);
    if (item) await this.updateItem(id, { pinned: !item.pinned });
  },

  /* ---- Coffre : recherche, filtres, grille 2 colonnes ---- */
  buildVaultList() {
    const container = document.createElement("div");
    container.className = "cs-vault-wrap";
    container.innerHTML = `
      <input type="search" id="cs-search" class="cs-search-input" placeholder="${escapeAttr(this.t("ui.searchPlaceholder"))}" />
      <div class="cs-chip-row" id="cs-cat-chips"></div>
      <div class="cs-chip-row" id="cs-codelang-chips" hidden></div>
      <div class="cs-toggle-row">
        <button class="cs-toggle-btn" id="cs-fav-toggle" type="button">${ICONS.star}<span>${escapeHtml(this.t("ui.filterFavoritesLabel"))}</span></button>
        <button class="cs-toggle-btn" id="cs-pin-toggle" type="button">${ICONS.pin}<span>${escapeHtml(this.t("ui.filterPinnedLabel"))}</span></button>
      </div>
      <div class="cs-vault-grid" id="cs-vault-list"></div>
    `;
    this.vaultContainer = container.querySelector("#cs-vault-list");
    this.catChipsContainer = container.querySelector("#cs-cat-chips");
    this.codeLangChipsContainer = container.querySelector("#cs-codelang-chips");

    container.querySelector("#cs-search").addEventListener("input", (e) => {
      this.filters.search = e.target.value.trim().toLowerCase();
      this.refreshVault();
    });
    container.querySelector("#cs-fav-toggle").addEventListener("click", (e) => {
      this.filters.onlyFavorites = !this.filters.onlyFavorites;
      e.currentTarget.classList.toggle("active", this.filters.onlyFavorites);
      this.refreshVault();
    });
    container.querySelector("#cs-pin-toggle").addEventListener("click", (e) => {
      this.filters.onlyPinned = !this.filters.onlyPinned;
      e.currentTarget.classList.toggle("active", this.filters.onlyPinned);
      this.refreshVault();
    });

    this.renderCategoryChips();
    this.refreshVault();
    return container;
  },

  renderCategoryChips() {
    const cats = this.data.categories;
    const html = [`<button class="cs-chip active" data-cat="all">${escapeHtml(this.t("ui.filterAllLabel"))}</button>`]
      .concat(
        cats.map(
          (c) =>
            `<button class="cs-chip" data-cat="${c.id}" style="--chip-color:${c.color}">${ICONS[c.icon] || ""}${escapeHtml(this.t(`categories.${c.id}`))}</button>`
        )
      )
      .join("");
    this.catChipsContainer.innerHTML = html;
    this.catChipsContainer.querySelectorAll(".cs-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        this.filters.category = chip.dataset.cat;
        this.filters.codeLang = "all";
        this.catChipsContainer.querySelectorAll(".cs-chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        this.refreshVault();
      });
    });
  },

  renderCodeLangChips(items) {
    const codeItems = items.filter((i) => i.category === "code" && i.codeLang);
    if (this.filters.category !== "code" || codeItems.length === 0) {
      this.codeLangChipsContainer.hidden = true;
      return;
    }
    const langs = [...new Set(codeItems.map((i) => i.codeLang))];
    const html = [`<button class="cs-chip cs-chip--sm ${this.filters.codeLang === "all" ? "active" : ""}" data-lang="all">${escapeHtml(this.t("ui.filterAllCodeLabel"))}</button>`]
      .concat(langs.map((l) => `<button class="cs-chip cs-chip--sm ${this.filters.codeLang === l ? "active" : ""}" data-lang="${l}">${CODE_LANG_LABELS[l] || l}</button>`))
      .join("");
    this.codeLangChipsContainer.innerHTML = html;
    this.codeLangChipsContainer.hidden = false;
    this.codeLangChipsContainer.querySelectorAll(".cs-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        this.filters.codeLang = chip.dataset.lang;
        this.codeLangChipsContainer.querySelectorAll(".cs-chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        this.refreshVault();
      });
    });
  },

  async refreshVault() {
    if (!this.vaultContainer) return;
    const allItems = await this.getItems();
    this.renderCodeLangChips(allItems);

    let items = [...allItems];
    const f = this.filters;
    if (f.category !== "all") items = items.filter((i) => i.category === f.category);
    if (f.category === "code" && f.codeLang !== "all") items = items.filter((i) => i.codeLang === f.codeLang);
    if (f.onlyFavorites) items = items.filter((i) => i.favorite);
    if (f.onlyPinned) items = items.filter((i) => i.pinned);
    if (f.search) {
      items = items.filter((i) => {
        const hay = [i.text, i.fileName].filter(Boolean).join(" ").toLowerCase();
        if (hay.includes(f.search)) return true;
        if (i.category === "links" && i.text) {
          try {
            return new URL(i.text).hostname.toLowerCase().includes(f.search);
          } catch {
            return false;
          }
        }
        return false;
      });
    }
    items.sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned) || new Date(b.createdAt) - new Date(a.createdAt));

    if (items.length === 0) {
      const msgKey = allItems.length === 0 ? "ui.emptyVault" : "ui.noResults";
      this.vaultContainer.innerHTML = `<p class="cs-empty cs-empty--grid">${escapeHtml(this.t(msgKey))}</p>`;
      return;
    }

    this.vaultContainer.innerHTML = items.map((i) => this.buildGridCardHtml(i)).join("");
    this.vaultContainer.querySelectorAll(".cs-grid-card").forEach((card) => {
      card.addEventListener("click", () => this.openDetail(card.dataset.id));
    });
  },

  buildGridCardHtml(item) {
    const cat = this.data.categories.find((c) => c.id === item.category) || this.data.categories[0];
    const catLabel = this.t(`categories.${cat.id}`);
    const badges = `${item.pinned ? ICONS.pin : ""}${item.favorite ? ICONS.star : ""}`;

    let preview;
    if (item.category === "images") {
      preview = `<img class="cs-grid-thumb" src="${item.dataUrl}" alt="${escapeAttr(item.fileName || "image")}" loading="lazy" />`;
    } else if (item.category === "documents") {
      const kindLabel = item.fileKind === "other" ? this.t("ui.fileKindOther") : FILE_KIND_LABELS[item.fileKind] || "";
      preview = `<div class="cs-grid-doc">${ICONS.document}<span class="cs-grid-doc-name">${escapeHtml(item.fileName || "")}</span><span class="cs-grid-code-badge">${escapeHtml(kindLabel)}</span></div>`;
    } else {
      preview = `<div class="cs-grid-preview-text">${escapeHtml(item.text || "")}</div>`;
    }
    const codeBadge = item.category === "code" && item.codeLang && CODE_LANG_LABELS[item.codeLang]
      ? `<span class="cs-grid-code-badge">${CODE_LANG_LABELS[item.codeLang]}</span>` : "";

    return `
      <article class="cs-grid-card" data-id="${item.id}">
        <div class="cs-grid-top">
          <span class="cs-tag cs-tag--sm" style="--tag-color:${cat.color}">${ICONS[cat.icon] || ""}${escapeHtml(catLabel)}</span>
          <div class="cs-grid-badges">${badges}</div>
        </div>
        ${preview}
        ${codeBadge}
      </article>`;
  },

  /* ---- Fiche détail (ouverte au clic, actions tout en haut) ---- */
  async openDetail(id) {
    const items = await this.getItems();
    const item = items.find((i) => i.id === id);
    if (!item) return;
    this.detailEditing = false;
    this.renderDetailModal(item);
    this.showOverlay();
  },

  renderDetailModal(item) {
    const cat = this.data.categories.find((c) => c.id === item.category) || this.data.categories[0];
    const catLabel = this.t(`categories.${cat.id}`);
    const codeSuffix = item.category === "code" && item.codeLang && CODE_LANG_LABELS[item.codeLang] ? ` · ${CODE_LANG_LABELS[item.codeLang]}` : "";
    const dateStr = new Date(item.createdAt).toLocaleString(LOCALE_MAP[this.getLang()] || "fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
    });

    let bodyHtml;
    if (this.detailEditing) {
      bodyHtml = this.buildEditFormHtml(item);
    } else if (item.category === "images") {
      bodyHtml = `<div class="cs-modal-content-image"><img src="${item.dataUrl}" alt="${escapeAttr(item.fileName || "image")}" /></div>`;
    } else if (item.category === "documents") {
      const kindLabel = item.fileKind === "other" ? this.t("ui.fileKindOther") : FILE_KIND_LABELS[item.fileKind] || "";
      bodyHtml = `
        <div class="cs-modal-doc">
          ${ICONS.document}
          <p class="cs-modal-doc-name">${escapeHtml(item.fileName || "")}</p>
          <p class="cs-modal-doc-kind">${escapeHtml(kindLabel)}</p>
          <a class="cs-btn cs-btn--ghost" href="${item.dataUrl}" download="${escapeAttr(item.fileName || "fichier")}">${ICONS.upload}${escapeHtml(this.t("ui.downloadLabel"))}</a>
        </div>`;
    } else {
      bodyHtml = `<div class="cs-modal-content-text">${escapeHtml(item.text || "")}</div>`;
    }

    const actionBar = this.detailEditing
      ? ""
      : `
      <div class="cs-modal-toolbar">
        <span class="cs-tag" style="--tag-color:${cat.color}">${ICONS[cat.icon] || ""}${escapeHtml(catLabel)}${codeSuffix}</span>
        <button class="cs-icon-btn ${item.favorite ? "cs-icon-btn--active" : ""}" data-act="favorite" title="${escapeAttr(this.t("ui.favoriteTooltip"))}">${ICONS.star}</button>
        <button class="cs-icon-btn ${item.pinned ? "cs-icon-btn--active" : ""}" data-act="pin" title="${escapeAttr(this.t("ui.pinTooltip"))}">${ICONS.pin}</button>
        <button class="cs-icon-btn" data-act="edit" title="${escapeAttr(this.t("ui.editTooltip"))}">${ICONS.edit}</button>
        <button class="cs-icon-btn" data-act="share" title="${escapeAttr(this.t("ui.shareTooltip"))}">${ICONS.share}</button>
        ${item.text ? `<button class="cs-icon-btn" data-act="copy" title="${escapeAttr(this.t("ui.copyTooltip"))}">${ICONS.copy}</button>` : ""}
        <button class="cs-icon-btn" data-act="delete" title="${escapeAttr(this.t("ui.deleteTooltip"))}">${ICONS.trash}</button>
        <button class="cs-icon-btn cs-modal-close" data-act="close" title="${escapeAttr(this.t("ui.closeTooltip"))}">${ICONS.close}</button>
      </div>`;

    this.overlay.innerHTML = `<div class="cs-modal">${actionBar}${bodyHtml}${this.detailEditing ? "" : `<p class="cs-modal-date">${dateStr}</p>`}</div>`;
    this.bindDetailEvents(item);
  },

  buildEditFormHtml(item) {
    const isBinary = item.category === "images" || item.category === "documents";
    const catOptions = this.data.categories
      .filter((c) => (isBinary ? c.id === "images" || c.id === "documents" : true))
      .map((c) => `<option value="${c.id}" ${item.category === c.id ? "selected" : ""}>${escapeHtml(this.t(`categories.${c.id}`))}</option>`)
      .join("");

    if (isBinary) {
      return `
        <div class="cs-modal-edit">
          <input type="text" id="cs-edit-filename" class="cs-edit-select" value="${escapeAttr(item.fileName || "")}" />
          <select id="cs-edit-category" class="cs-edit-select" style="margin-top:0.6rem;">${catOptions}</select>
          <div class="cs-modal-actions">
            <button class="cs-btn cs-btn--ghost" data-act="cancel-edit">${escapeHtml(this.t("ui.cancelEditTooltip"))}</button>
            <button class="cs-btn cs-btn--primary" data-act="save-edit">${escapeHtml(this.t("ui.saveTooltip"))}</button>
          </div>
        </div>`;
    }
    return `
      <div class="cs-modal-edit">
        <textarea id="cs-edit-textarea" class="cs-edit-textarea" rows="6">${escapeHtml(item.text || "")}</textarea>
        <div class="cs-row" style="margin-top:0.6rem;">
          <select id="cs-edit-category" class="cs-edit-select">${catOptions}</select>
          <button class="cs-btn cs-btn--ghost" id="cs-edit-autodetect" type="button" title="${escapeAttr(this.t("ui.smartPasteBtn"))}">${ICONS.wand}</button>
        </div>
        <div class="cs-modal-actions">
          <button class="cs-btn cs-btn--ghost" data-act="cancel-edit">${escapeHtml(this.t("ui.cancelEditTooltip"))}</button>
          <button class="cs-btn cs-btn--primary" data-act="save-edit">${escapeHtml(this.t("ui.saveTooltip"))}</button>
        </div>
      </div>`;
  },

  bindDetailEvents(item) {
    const modal = this.overlay.querySelector(".cs-modal");
    modal.querySelectorAll("[data-act]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const act = btn.dataset.act;
        if (act === "close") return this.closeOverlay();
        if (act === "favorite") {
          await this.toggleFavorite(item.id);
          const fresh = (await this.getItems()).find((i) => i.id === item.id);
          if (fresh) this.renderDetailModal(fresh);
          return;
        }
        if (act === "pin") {
          await this.togglePinned(item.id);
          const fresh = (await this.getItems()).find((i) => i.id === item.id);
          if (fresh) this.renderDetailModal(fresh);
          return;
        }
        if (act === "edit") {
          this.detailEditing = true;
          this.renderDetailModal(item);
          return;
        }
        if (act === "cancel-edit") {
          this.detailEditing = false;
          this.renderDetailModal(item);
          return;
        }
        if (act === "share") return this.shareItem(item);
        if (act === "copy") {
          await navigator.clipboard.writeText(item.text || "");
          this.toast(this.t("ui.copiedToast"));
          return;
        }
        if (act === "delete") {
          await this.deleteItem(item.id);
          this.closeOverlay();
          return;
        }
        if (act === "save-edit") return this.saveEditFromModal(item);
      });
    });

    if (this.detailEditing) {
      const autodetectBtn = modal.querySelector("#cs-edit-autodetect");
      autodetectBtn?.addEventListener("click", () => {
        const ta = modal.querySelector("#cs-edit-textarea");
        const { category, codeLang } = detectCategory(ta.value);
        modal.querySelector("#cs-edit-category").value = category;
        this._pendingCodeLang = codeLang;
      });
    }
  },

  async saveEditFromModal(item) {
    const modal = this.overlay.querySelector(".cs-modal");
    const catSelect = modal.querySelector("#cs-edit-category");
    const newCategory = catSelect ? catSelect.value : item.category;
    const patch = { category: newCategory };

    const ta = modal.querySelector("#cs-edit-textarea");
    if (ta) {
      patch.text = ta.value;
      patch.codeLang = newCategory === "code" ? this._pendingCodeLang || item.codeLang || detectCodeLang(ta.value) || "other" : undefined;
    }
    const fnInput = modal.querySelector("#cs-edit-filename");
    if (fnInput) patch.fileName = fnInput.value;

    await this.updateItem(item.id, patch);
    this.detailEditing = false;
    const fresh = (await this.getItems()).find((i) => i.id === item.id);
    if (fresh) this.renderDetailModal(fresh);
  },

  /* ---- Partage ---- */
  async shareItem(item) {
    const isBinary = item.category === "images" || item.category === "documents";
    if (navigator.share) {
      try {
        if (isBinary && item.dataUrl) {
          const file = await this.dataUrlToFile(item.dataUrl, item.fileName || "clipsafe-file", item.mime);
          if (navigator.canShare && navigator.canShare({ files: [file] })) {
            await navigator.share({ files: [file] });
            return;
          }
        } else if (item.text) {
          await navigator.share({ text: item.text });
          return;
        }
      } catch (err) {
        if (err && err.name === "AbortError") return;
      }
    }
    this.renderShareFallback(item);
    this.showOverlay();
  },

  async dataUrlToFile(dataUrl, fileName, mime) {
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    return new File([blob], fileName, { type: mime || blob.type });
  },

  renderShareFallback(item) {
    if (item.category === "images" || item.category === "documents") {
      this.overlay.innerHTML = `
        <div class="cs-modal">
          <div class="cs-modal-toolbar">
            <strong>${escapeHtml(this.t("ui.shareVia"))}</strong>
            <button class="cs-icon-btn cs-modal-close" data-act="close">${ICONS.close}</button>
          </div>
          <p class="cs-modal-message">${escapeHtml(this.t("ui.shareBinaryUnsupported"))}</p>
        </div>`;
      this.overlay.querySelector("[data-act='close']").addEventListener("click", () => this.closeOverlay());
      return;
    }
    const text = encodeURIComponent(item.text || "");
    const links = [
      { label: "WhatsApp", url: `https://wa.me/?text=${text}`, icon: ICONS.whatsapp },
      { label: "Telegram", url: `https://t.me/share/url?url=&text=${text}`, icon: ICONS.telegram },
      { label: "X (Twitter)", url: `https://twitter.com/intent/tweet?text=${text}`, icon: ICONS.x },
      { label: "Email", url: `mailto:?body=${text}`, icon: ICONS.mail },
      { label: "SMS", url: `sms:?body=${text}`, icon: ICONS.sms },
    ];
    this.overlay.innerHTML = `
      <div class="cs-modal">
        <div class="cs-modal-toolbar">
          <strong>${escapeHtml(this.t("ui.shareVia"))}</strong>
          <button class="cs-icon-btn cs-modal-close" data-act="close">${ICONS.close}</button>
        </div>
        <div class="cs-share-list">
          ${links.map((l) => `<a class="cs-share-item" href="${l.url}" target="_blank" rel="noopener">${l.icon}<span>${escapeHtml(l.label)}</span></a>`).join("")}
          <button class="cs-share-item" id="cs-share-copy" type="button">${ICONS.copy}<span>${escapeHtml(this.t("ui.shareCopyLink"))}</span></button>
        </div>
      </div>`;
    this.overlay.querySelector("[data-act='close']").addEventListener("click", () => this.closeOverlay());
    this.overlay.querySelector("#cs-share-copy").addEventListener("click", async () => {
      await navigator.clipboard.writeText(item.text || "");
      this.toast(this.t("ui.copiedToast"));
      this.closeOverlay();
    });
  },

  /* ---- Premium / licence / essai ---- */
  buildPremiumBlock() {
    const box = document.createElement("div");
    box.className = "cs-premium";
    const premium = this.data.premium;

    const renderState = async () => {
      const isPremium = await PremiumLock.isPremium();
      if (isPremium) {
        const expiresAt = await PremiumLock.getExpiresAt();
        const activeMsg = expiresAt
          ? this.t("ui.premiumActiveUntil").replace(
              "{date}",
              new Date(expiresAt).toLocaleDateString(LOCALE_MAP[this.getLang()] || "fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" })
            )
          : this.t("ui.premiumActive");
        box.innerHTML = `<div class="cs-premium-active">${ICONS.lock}<span>${escapeHtml(activeMsg)}</span></div>`;
        return;
      }
      const features = this.t("premium.features");
      const licenseLabel = this.t("premium.licenseLabel");
      const trialDays = premium.trialDays ?? 7;
      const start = await TrialLock.getStart();
      let trialLine = "";
      if (start) {
        const daysLeft = Math.max(0, trialDays - Math.floor((Date.now() - start) / 86400000));
        trialLine = `<p class="cs-trial-status">${escapeHtml(this.t("ui.trialDaysLeftLabel").replace("{left}", daysLeft).replace("{total}", trialDays))}</p>`;
      }
      box.innerHTML = `
        ${trialLine}
        <ul class="cs-premium-features">${(Array.isArray(features) ? features : []).map((f) => `<li>${escapeHtml(f)}</li>`).join("")}</ul>
        <a class="cs-btn cs-btn--premium" href="${premium.kikiapayLink}" target="_blank" rel="noopener">
          ${escapeHtml(licenseLabel)} — ${premium.priceFcfa} FCFA · ${premium.priceUsd} $ · ${premium.priceEur} €
        </a>
        <button class="cs-btn cs-btn--ghost" id="cs-have-license-btn" type="button" style="width:100%;margin-top:0.5rem;">${escapeHtml(this.t("ui.haveLicenseBtn"))}</button>
      `;
      box.querySelector("#cs-have-license-btn").addEventListener("click", () => this.openLicenseModal(false));
    };

    if (premium.enabled) renderState();
    return box;
  },

  async openLicenseModal(fromExpiry) {
    this.licenseFromExpiry = !!fromExpiry;
    this.renderLicenseModal();
    this.showOverlay();
  },

  renderLicenseModal() {
    const trialDays = this.data.premium.trialDays ?? 7;
    const titleText = this.licenseFromExpiry ? this.t("ui.trialExpiredTitle") : this.t("ui.licenseModalTitle");
    const message = this.licenseFromExpiry ? this.t("ui.trialExpiredMessage").replace("{days}", trialDays) : "";
    this.overlay.innerHTML = `
      <div class="cs-modal">
        <div class="cs-modal-toolbar">
          <strong>${escapeHtml(titleText)}</strong>
          <button class="cs-icon-btn cs-modal-close" data-act="close" title="${escapeAttr(this.t("ui.closeTooltip"))}">${ICONS.close}</button>
        </div>
        ${message ? `<p class="cs-modal-message">${escapeHtml(message)}</p>` : ""}
        <div class="cs-license-input-row">
          <input type="text" id="cs-license-input" class="cs-edit-select" placeholder="${escapeAttr(this.t("ui.licenseInputPlaceholder"))}"
            autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
          <button class="cs-btn cs-btn--ghost cs-license-paste-btn" id="cs-license-paste-btn" type="button" title="${escapeAttr(this.t("ui.pasteBtn"))}">${ICONS.copy}</button>
        </div>
        <p class="cs-modal-error" id="cs-license-error"></p>
        <div class="cs-modal-actions">
          <button class="cs-btn cs-btn--ghost" data-act="close">${escapeHtml(this.t("ui.licenseCancelBtn"))}</button>
          <button class="cs-btn cs-btn--primary" data-act="validate-license">${escapeHtml(this.t("ui.licenseValidateBtn"))}</button>
        </div>
        <a class="cs-modal-buy-link" href="${this.data.premium.kikiapayLink}" target="_blank" rel="noopener">${escapeHtml(this.t("premium.licenseLabel"))} — ${this.data.premium.priceFcfa} FCFA</a>
      </div>`;
    this.overlay.querySelectorAll("[data-act='close']").forEach((b) => b.addEventListener("click", () => this.closeOverlay()));
    this.overlay.querySelector("[data-act='validate-license']").addEventListener("click", () => this.validateLicenseKey());
    this.overlay.querySelector("#cs-license-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") this.validateLicenseKey();
    });
    this.overlay.querySelector("#cs-license-paste-btn").addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        this.overlay.querySelector("#cs-license-input").value = text;
      } catch {
        this.toast(this.t("ui.clipboardDenied"));
      }
    });
  },

  async validateLicenseKey() {
    const input = this.overlay.querySelector("#cs-license-input");
    const errorEl = this.overlay.querySelector("#cs-license-error");
    // Les clés sont générées en MAJUSCULES sans espaces ; on normalise la
    // saisie pour rester tolérant si la clé a été tapée à la main plutôt
    // que collée (casse, espace parasite au milieu, etc.).
    const normalized = input.value.replace(/\s+/g, "").toUpperCase();
    if (!normalized) return;
    const hash = await CryptoBox.sha256Hex(normalized);
    const keys = this.data.premium.licenseKeys || [];
    const match = keys.find((k) => k.hash === hash);
    if (!match) {
      errorEl.textContent = this.t("ui.licenseInvalid");
      input.value = "";
      return;
    }
    await PremiumLock.grant(match.hash, match.durationDays || 0);
    this.toast(this.t("ui.licenseGranted"));
    this.closeOverlay();
    this.render();
  },

  /* ---- Pied de page ---- */
  renderFooter() {
    const footer = document.createElement("footer");
    footer.className = "cs-footer";
    const buttons = this.data.footer.buttons
      .map((b) => `<a class="cs-footer-btn" style="--btn-color:${b.color}" href="${b.url}" target="_blank" rel="noopener">${ICONS[b.icon] || ""}<span>${escapeHtml(b.label)}</span></a>`)
      .join("");
    const emailBtn = this.data.footer.buttons.find((b) => b.id === "email");
    footer.innerHTML = `
      <div class="cs-footer-buttons">${buttons}</div>
      <p class="cs-footer-cta">${escapeHtml(this.t("footer.ctaText"))} <a href="${emailBtn ? emailBtn.url : "#"}">${escapeHtml(this.t("footer.ctaLink"))}</a></p>
      <p class="cs-footer-text">${escapeHtml(this.data.footer.text)}</p>
    `;
    return footer;
  },

  /* ---- Divers ---- */
  toast(message) {
    const el = document.createElement("div");
    el.className = "cs-toast";
    el.textContent = message;
    document.body.appendChild(el);
    requestAnimationFrame(() => el.classList.add("cs-toast--visible"));
    setTimeout(() => {
      el.classList.remove("cs-toast--visible");
      setTimeout(() => el.remove(), 300);
    }, 2200);
  },

  registerServiceWorker() {
    if ("serviceWorker" in navigator) {
      window.addEventListener("load", () => {
        navigator.serviceWorker.register("sw.js").catch(() => {});
      });
    }
  },
};

document.addEventListener("DOMContentLoaded", () => ClipSafeApp.init());
