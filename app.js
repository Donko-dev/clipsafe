/* =========================================================================
   ClipSafe — app.js
   Moteur applicatif de la page publique.
   Tout le contenu affiché provient de data.json : rien n'est codé en dur.
   ========================================================================= */

"use strict";

/* -------------------------------------------------------------------------
   0. Protections client basiques (dissuasives, pas absolues)
   Un site 100% statique livré au navigateur ne peut jamais empêcher un
   utilisateur déterminé d'inspecter son code : ceci ne fait que dissuader
   les clics accidentels / la curiosité occasionnelle.
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
   1. Utilitaires cryptographiques (Web Crypto API)
   ------------------------------------------------------------------------- */
const CryptoBox = {
  KEY_STORAGE: "cs_vault_key",

  async _getKey() {
    const stored = localStorage.getItem(this.KEY_STORAGE);
    if (stored) {
      const raw = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
      return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
    }
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    const exported = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    localStorage.setItem(this.KEY_STORAGE, btoa(String.fromCharCode(...exported)));
    return key;
  },

  async encrypt(plainText) {
    const key = await this._getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)
    );
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
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },
};

/* -------------------------------------------------------------------------
   2. Verrou d'état Premium
   La valeur est stockée sous une clé non explicite, accompagnée d'une
   signature dérivée d'un sel propre à l'appareil. Modifier "cs_px" à la
   main dans la console ne suffit pas : la signature ne correspondra plus
   et la valeur sera ignorée. Ceci reste une dissuasion côté client, pas
   une preuve cryptographique de paiement (qui nécessiterait un serveur).
   ------------------------------------------------------------------------- */
const PremiumLock = {
  FLAG_KEY: "cs_px",
  SIG_KEY: "cs_px_sig",
  SALT_KEY: "cs_px_salt",

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
    if (!flag || !sig) return false;
    const salt = await this._salt();
    const expected = await CryptoBox.sha256Hex(salt + ":" + flag);
    return expected === sig && flag === "granted";
  },

  async grant() {
    const salt = await this._salt();
    const sig = await CryptoBox.sha256Hex(salt + ":granted");
    localStorage.setItem(this.FLAG_KEY, "granted");
    localStorage.setItem(this.SIG_KEY, sig);
  },

  revoke() {
    localStorage.removeItem(this.FLAG_KEY);
    localStorage.removeItem(this.SIG_KEY);
  },
};

/* -------------------------------------------------------------------------
   3. Sanitisation des entrées (anti-XSS)
   ------------------------------------------------------------------------- */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

/* -------------------------------------------------------------------------
   4. Catégorisation automatique
   ------------------------------------------------------------------------- */
function detectCategory(text) {
  const trimmed = text.trim();
  const urlRegex = /^(https?:\/\/|www\.)[^\s]+$/i;
  const phoneRegex = /^[+()0-9\s.-]{6,20}$/;
  if (urlRegex.test(trimmed)) return "links";
  if (phoneRegex.test(trimmed) && /\d{4,}/.test(trimmed)) return "numbers";
  return "texts";
}

/* -------------------------------------------------------------------------
   5. Icônes SVG inline (pieds de page + catégories)
   ------------------------------------------------------------------------- */
const ICONS = {
  whatsapp:
    '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M17.5 14.4c-.3-.1-1.7-.9-2-1-.3-.1-.5-.1-.7.1-.2.3-.8 1-.9 1.2-.2.2-.3.2-.6.1-.3-.1-1.3-.5-2.4-1.5-.9-.8-1.5-1.8-1.6-2.1-.2-.3 0-.5.1-.6.1-.1.3-.3.4-.5.1-.1.2-.3.3-.5.1-.2 0-.4 0-.5-.1-.1-.7-1.6-.9-2.2-.2-.6-.5-.5-.7-.5h-.6c-.2 0-.5.1-.8.4-.3.3-1 1-1 2.4s1.1 2.8 1.2 3c.1.2 2.2 3.3 5.3 4.6.7.3 1.3.5 1.8.7.7.2 1.4.2 1.9.1.6-.1 1.7-.7 2-1.4.2-.7.2-1.3.2-1.4-.1-.2-.3-.2-.6-.3z"/><path fill="currentColor" d="M12 2C6.5 2 2 6.5 2 12c0 1.9.5 3.6 1.4 5.1L2 22l5-1.3c1.4.8 3.1 1.3 4.9 1.3 5.5 0 10-4.5 10-10S17.5 2 12 2zm0 18.2c-1.6 0-3.1-.4-4.4-1.2l-.3-.2-3 .8.8-2.9-.2-.3C4.2 14.9 3.8 13.5 3.8 12c0-4.5 3.7-8.2 8.2-8.2s8.2 3.7 8.2 8.2-3.7 8.2-8.2 8.2z"/></svg>',
  shop: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M4 4h16l-1.5 9h-13z" opacity=".25"/><path fill="currentColor" d="M6 22a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zm12 0a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM3 3h2l2.4 12.2a2 2 0 0 0 2 1.6h7.2a2 2 0 0 0 2-1.6L21 7H6"/></svg>',
  mail: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm1.4 2L12 12.5 19.6 7H4.4zM20 8.4l-7.4 5.4a1 1 0 0 1-1.2 0L4 8.4V18h16V8.4z"/></svg>',
  text: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M4 4h16v2H4zm0 6h16v2H4zm0 6h10v2H4z"/></svg>',
  link: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M10.6 13.4a1 1 0 0 1 0-1.4l3-3a1 1 0 1 1 1.4 1.4l-3 3a1 1 0 0 1-1.4 0zM8.5 15.5l-1 1a2.5 2.5 0 0 1-3.5-3.5l3-3a2.5 2.5 0 0 1 3.5 0 1 1 0 1 1-1.4 1.4.5.5 0 0 0-.7 0l-3 3a.5.5 0 0 0 .7.7l1-1a1 1 0 1 1 1.4 1.4zm7-7 1-1a2.5 2.5 0 0 1 3.5 3.5l-3 3a2.5 2.5 0 0 1-3.5 0 1 1 0 1 1 1.4-1.4.5.5 0 0 0 .7 0l3-3a.5.5 0 0 0-.7-.7l-1 1a1 1 0 1 1-1.4-1.4z"/></svg>',
  hash: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M9.5 3l-1 6H4v2h4.2l-.6 4H3v2h4.3l-1 5h2l1-5h4l-1 5h2l1-5H20v-2h-4.2l.6-4H21V9h-4.3l1-6h-2l-1 6h-4l1-6h-2zm.9 8h4l-.6 4h-4l.6-4z"/></svg>',
  copy: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M6 7h12l-1 14H7L6 7zm3-3h6l1 2H8l1-2zM9 9v9m3-9v9m3-9v9" fill="none" stroke="currentColor" stroke-width="0"/><path fill="currentColor" d="M9 9h2v9H9zm4 0h2v9h-2z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3H9V6a3 3 0 0 1 3-3z"/></svg>',
};

/* -------------------------------------------------------------------------
   6. Application principale
   ------------------------------------------------------------------------- */
const ClipSafeApp = {
  data: null,
  vaultKey: "cs_vault_items",

  async init() {
    this.root = document.getElementById("app-root");
    try {
      const res = await fetch("data.json", { cache: "no-store" });
      this.data = await res.json();
    } catch (err) {
      this.root.innerHTML = `<p class="cs-error">Impossible de charger la configuration (data.json).</p>`;
      return;
    }
    this.applyTheme();
    this.render();
    this.registerServiceWorker();
  },

  MODE_KEY: "cs_theme_mode",

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
    const mode = this.getMode();
    const colors = colorModes[mode] || colorModes.dark;
    const root = document.documentElement.style;
    Object.entries(colors).forEach(([k, v]) => root.setProperty(`--cs-${k}`, v));
    root.setProperty("--cs-font-display", fonts.display);
    root.setProperty("--cs-font-body", fonts.body);
    root.setProperty("--cs-font-mono", fonts.mono);
    root.setProperty("--cs-radius", radius);
    document.title = this.data.app.name + " — " + this.data.app.tagline;

    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", colors.bg);

    const favicon = document.getElementById("cs-favicon");
    if (favicon && this.data.branding?.faviconSvg) {
      favicon.href = "data:image/svg+xml," + encodeURIComponent(this.data.branding.faviconSvg);
    }
  },

  render() {
    this.root.innerHTML = "";
    const header = document.createElement("header");
    header.className = "cs-topbar";
    const currentMode = this.getMode();
    header.innerHTML = `
      <div class="cs-logo">${this.data.branding?.logoSvg || ""}</div>
      <span class="cs-appname">${escapeHtml(this.data.app.name)}</span>
      <button id="cs-theme-toggle" class="cs-theme-toggle" type="button" title="Changer de thème">
        ${currentMode === "dark" ? "☀️" : "🌙"}
      </button>
    `;
    header.querySelector("#cs-theme-toggle").addEventListener("click", () => {
      this.setMode(this.getMode() === "dark" ? "light" : "dark");
    });
    this.root.appendChild(header);

    const enabledSections = this.data.sections
      .filter((s) => s.enabled)
      .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));

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

    const titleTag = document.createElement("h2");
    titleTag.className = "cs-section-title";
    if (section.style?.bold) titleTag.style.fontWeight = "700";
    if (section.style?.italic) titleTag.style.fontStyle = "italic";
    if (section.style?.underline) titleTag.style.textDecoration = "underline";
    titleTag.textContent = section.title || "";
    wrap.appendChild(titleTag);

    if (section.subtitle) {
      const sub = document.createElement("p");
      sub.className = "cs-section-subtitle";
      sub.textContent = section.subtitle;
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

  buildCapture() {
    const box = document.createElement("div");
    box.className = "cs-capture";
    box.innerHTML = `
      <textarea id="cs-input" class="cs-textarea" rows="3"
        placeholder="Collez ou saisissez un texte, un lien ou un numéro…"></textarea>
      <div class="cs-capture-actions">
        <button id="cs-paste-btn" class="cs-btn cs-btn--ghost" type="button">Coller depuis le presse-papiers</button>
        <button id="cs-save-btn" class="cs-btn cs-btn--primary" type="button">Ajouter au coffre</button>
      </div>
    `;

    box.querySelector("#cs-paste-btn").addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        box.querySelector("#cs-input").value = text;
      } catch {
        this.toast("Autorisation presse-papiers refusée. Collez manuellement (Ctrl/Cmd+V).");
      }
    });

    box.querySelector("#cs-save-btn").addEventListener("click", async () => {
      const input = box.querySelector("#cs-input");
      const value = input.value.trim();
      if (!value) return;
      await this.addItem(value);
      input.value = "";
      this.refreshVault();
    });

    return box;
  },

  buildVaultList() {
    const container = document.createElement("div");
    container.id = "cs-vault-list";
    container.className = "cs-vault-list";
    this.vaultContainer = container;
    this.refreshVault();
    return container;
  },

  async getItems() {
    const raw = localStorage.getItem(this.vaultKey);
    if (!raw) return [];
    try {
      const decrypted = await CryptoBox.decrypt(raw);
      return JSON.parse(decrypted);
    } catch {
      return [];
    }
  },

  async saveItems(items) {
    const encrypted = await CryptoBox.encrypt(JSON.stringify(items));
    localStorage.setItem(this.vaultKey, encrypted);
  },

  async addItem(text) {
    const items = await this.getItems();
    items.unshift({
      id: crypto.randomUUID(),
      text,
      category: detectCategory(text),
      createdAt: new Date().toISOString(),
    });
    await this.saveItems(items);
  },

  async deleteItem(id) {
    const items = await this.getItems();
    await this.saveItems(items.filter((i) => i.id !== id));
    this.refreshVault();
  },

  async refreshVault() {
    if (!this.vaultContainer) return;
    const items = await this.getItems();
    const categories = this.data.categories;

    if (items.length === 0) {
      this.vaultContainer.innerHTML = `<p class="cs-empty">Votre coffre est vide pour l'instant.</p>`;
      return;
    }

    this.vaultContainer.innerHTML = items
      .map((item) => {
        const cat = categories.find((c) => c.id === item.category) || categories[0];
        const date = new Date(item.createdAt).toLocaleString("fr-FR", {
          day: "2-digit",
          month: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        });
        return `
          <article class="cs-card" data-id="${item.id}">
            <div class="cs-card-content">${escapeHtml(item.text)}</div>
            <div class="cs-card-seal"></div>
            <div class="cs-card-meta">
              <span class="cs-tag" style="--tag-color:${cat.color}">${ICONS[cat.icon] || ""}${cat.label}</span>
              <span class="cs-date">${date}</span>
              <div class="cs-card-buttons">
                <button class="cs-icon-btn" data-action="copy" title="Copier">${ICONS.copy}</button>
                <button class="cs-icon-btn" data-action="delete" title="Supprimer">${ICONS.trash}</button>
              </div>
            </div>
          </article>
        `;
      })
      .join("");

    this.vaultContainer.querySelectorAll("[data-action='copy']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        const card = e.target.closest(".cs-card");
        const text = card.querySelector(".cs-card-content").textContent;
        await navigator.clipboard.writeText(text);
        this.toast("Copié !");
      });
    });
    this.vaultContainer.querySelectorAll("[data-action='delete']").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const card = e.target.closest(".cs-card");
        this.deleteItem(card.dataset.id);
      });
    });
  },

  buildPremiumBlock() {
    const box = document.createElement("div");
    box.className = "cs-premium";
    const premium = this.data.premium;

    const renderState = async () => {
      const isPremium = await PremiumLock.isPremium();
      box.innerHTML = isPremium
        ? `<div class="cs-premium-active">${ICONS.lock}<span>Licence à vie activée — merci pour votre confiance.</span></div>`
        : `
          <ul class="cs-premium-features">
            ${premium.features.map((f) => `<li>${escapeHtml(f)}</li>`).join("")}
          </ul>
          <a class="cs-btn cs-btn--premium" href="${premium.kikiapayLink}" target="_blank" rel="noopener">
            ${premium.licenseLabel} — ${premium.priceFcfa} FCFA · ${premium.priceUsd} $ · ${premium.priceEur} €
          </a>
        `;
    };

    if (premium.enabled) {
      renderState();
    } else {
      box.innerHTML = "";
    }
    return box;
  },

  renderFooter() {
    const footer = document.createElement("footer");
    footer.className = "cs-footer";
    const buttons = this.data.footer.buttons
      .map(
        (b) => `
        <a class="cs-footer-btn" style="--btn-color:${b.color}" href="${b.url}" target="_blank" rel="noopener">
          ${ICONS[b.icon] || ""}<span>${escapeHtml(b.label)}</span>
        </a>`
      )
      .join("");
    footer.innerHTML = `
      <div class="cs-footer-buttons">${buttons}</div>
      <p class="cs-footer-text">${escapeHtml(this.data.footer.text)}</p>
    `;
    return footer;
  },

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
        navigator.serviceWorker.register("sw.js").catch(() => {
          /* échec silencieux : l'app reste fonctionnelle en ligne */
        });
      });
    }
  },
};

document.addEventListener("DOMContentLoaded", () => ClipSafeApp.init());
