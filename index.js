/**
 * @kawanua/license-sdk  v1.0.0
 * ─────────────────────────────────────────────────────────────────
 * Drop-in SDK untuk klien yang menggunakan lisensi Kawanua.
 *
 * Cara pakai:
 *   <script src="https://cdn.kawanua.id/sdk/license.min.js"></script>
 *   <script>
 *     KawanuaLicense.init({ token: 'eyJ...' });
 *   </script>
 *
 * Atau via ESM:
 *   import { KawanuaLicense } from '@kawanua/license-sdk';
 *   KawanuaLicense.init({ token: 'eyJ...' });
 * ─────────────────────────────────────────────────────────────────
 */

(function (global, factory) {
  // UMD wrapper — support <script>, CommonJS, dan ESM
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    define(factory);
  } else {
    global.KawanuaLicense = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ─── Konstanta ──────────────────────────────────────────────────

  /**
   * Public key RS256 dari server lisensi Kawanua.
   * Klien hanya bisa VERIFY — tidak bisa forge token baru.
   * Ganti dengan public key aktual setelah generate keypair di server.
   */
  const KAWANUA_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJF
... (ganti dengan public key RS256 aktual dari server kamu) ...
-----END PUBLIC KEY-----`;

  /**
   * URL endpoint JWKS publik — alternatif lebih dinamis dari hardcode PEM.
   * SDK akan fetch public key dari sini jika PEM tidak di-set.
   * Endpoint ini harus tersedia di server Kawanua.
   */
  const JWKS_URL = "https://lisensi.kawanua.workers.dev/.well-known/jwks.json";

  /** Feature map per plan — single source of truth */
  const PLAN_FEATURES = {
    starter: {
      remove_branding: false, // "Powered by Kawanua" tetap muncul
      custom_domain: false,
      api_access: false,
      max_users: 5,
      analytics: "basic",
      white_label: false,
      priority_support: false,
    },
    professional: {
      remove_branding: true, // Branding disembunyikan
      custom_domain: false,
      api_access: true,
      max_users: 50,
      analytics: "advanced",
      white_label: false,
      priority_support: true,
    },
    enterprise: {
      remove_branding: true,
      custom_domain: true,
      api_access: true,
      max_users: Infinity,
      analytics: "advanced",
      white_label: true,
      priority_support: true,
    },
  };

  // ─── State internal ─────────────────────────────────────────────

  let _state = {
    initialized: false,
    valid: false,
    plan: null, // 'starter' | 'professional' | 'enterprise'
    features: {}, // merged dari PLAN_FEATURES + JWT claims
    license: null, // raw decoded payload
    expiresAt: null,
    _refreshTimer: null,
  };

  // ─── Crypto: decode & verify JWT RS256 ─────────────────────────

  /**
   * Decode JWT payload tanpa verify (hanya untuk read claims).
   * JANGAN gunakan ini untuk security check.
   */
  function _decodePayload(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) throw new Error("Invalid JWT structure");
      // Base64url → Base64 → JSON
      const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      const padded = base64.padEnd(
        base64.length + ((4 - (base64.length % 4)) % 4),
        "=",
      );
      return JSON.parse(atob(padded));
    } catch {
      return null;
    }
  }

  /**
   * Import public key RS256 dari PEM string ke CryptoKey.
   * Menggunakan Web Crypto API (tersedia di semua browser modern).
   */
  async function _importPublicKey(pem) {
    const pemBody = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");
    const der = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
    return crypto.subtle.importKey(
      "spki",
      der.buffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  }

  /**
   * Fetch public key dari JWKS endpoint.
   * Fallback jika PEM belum di-hardcode (mode dinamis).
   */
  async function _fetchPublicKeyFromJWKS(kid) {
    const res = await fetch(JWKS_URL, { cache: "force-cache" });
    const jwks = await res.json();
    const jwk = kid ? jwks.keys.find((k) => k.kid === kid) : jwks.keys[0];
    if (!jwk) throw new Error("No matching key found in JWKS");
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  }

  /**
   * Verifikasi signature JWT dengan RS256.
   * Returns true jika valid, false jika tidak.
   */
  async function _verifySignature(token, publicKey) {
    const [headerB64, payloadB64, sigB64] = token.split(".");
    const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = Uint8Array.from(
      atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );
    return crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      message,
    );
  }

  /**
   * Full JWT verification pipeline:
   * 1. Decode header untuk ambil kid & alg
   * 2. Verify signature (RS256)
   * 3. Cek expiry
   * Returns decoded payload atau throws Error.
   */
  async function _verifyToken(token) {
    if (!token || typeof token !== "string") {
      throw new Error("Token tidak valid.");
    }

    // Decode header
    const headerRaw = token.split(".")[0];
    const headerPad = headerRaw.replace(/-/g, "+").replace(/_/g, "/");
    const header = JSON.parse(
      atob(
        headerPad.padEnd(
          headerPad.length + ((4 - (headerPad.length % 4)) % 4),
          "=",
        ),
      ),
    );

    if (header.alg !== "RS256") {
      throw new Error(
        `Algoritma JWT tidak didukung: ${header.alg}. Hanya RS256 yang diterima.`,
      );
    }

    // Import public key (prioritas: hardcode PEM → JWKS endpoint)
    let publicKey;
    const hasPem = KAWANUA_PUBLIC_KEY_PEM.includes("..."); // placeholder check
    if (!hasPem) {
      publicKey = await _importPublicKey(KAWANUA_PUBLIC_KEY_PEM);
    } else {
      publicKey = await _fetchPublicKeyFromJWKS(header.kid);
    }

    // Verify signature
    const isValid = await _verifySignature(token, publicKey);
    if (!isValid) {
      throw new Error(
        "Signature JWT tidak valid. Token mungkin telah dimanipulasi.",
      );
    }

    // Decode payload
    const payload = _decodePayload(token);
    if (!payload) throw new Error("Payload JWT tidak dapat dibaca.");

    // Cek expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new Error(
        "Lisensi telah kedaluwarsa. Silakan hubungi administrator.",
      );
    }

    // Cek not-before
    if (payload.nbf && payload.nbf > now) {
      throw new Error("Token belum aktif (nbf). Periksa waktu sistem kamu.");
    }

    return payload;
  }

  // ─── Feature resolution ─────────────────────────────────────────

  /**
   * Merge feature defaults dari PLAN_FEATURES dengan override dari JWT claims.
   * JWT claims selalu menang atas default plan (fine-grained control).
   */
  function _resolveFeatures(plan, jwtFeatures = {}) {
    const defaults = PLAN_FEATURES[plan] ?? PLAN_FEATURES["starter"];
    return Object.freeze({ ...defaults, ...jwtFeatures });
  }

  // ─── Branding injection ─────────────────────────────────────────

  const BRANDING_ID = "__kawanua_powered_by";
  const BRANDING_HTML = `
    <a
      id="${BRANDING_ID}"
      href="https://kawanua.id"
      target="_blank"
      rel="noopener noreferrer"
      style="
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 11px;
        color: #6b7280;
        text-decoration: none;
        padding: 4px 8px;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        background: #f9fafb;
        transition: opacity 0.2s ease;
        position: fixed;
        bottom: 12px;
        right: 12px;
        z-index: 9999;
      "
      onmouseover="this.style.opacity='0.7'"
      onmouseout="this.style.opacity='1'"
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Powered by <strong style="color:#374151">Kawanua</strong>
    </a>
  `;

  function _injectBranding() {
    if (document.getElementById(BRANDING_ID)) return;
    const wrapper = document.createElement("div");
    wrapper.innerHTML = BRANDING_HTML.trim();
    document.body.appendChild(wrapper.firstElementChild);
  }

  function _removeBranding() {
    const el = document.getElementById(BRANDING_ID);
    if (el) el.remove();
  }

  function _applyBranding(features) {
    // Pastikan DOM sudah ready
    const apply = () => {
      if (features.remove_branding) {
        _removeBranding();
      } else {
        _injectBranding();
      }
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", apply, { once: true });
    } else {
      apply();
    }
  }

  // ─── Auto-refresh ────────────────────────────────────────────────

  /**
   * Schedule auto-refresh token sebelum expiry.
   * onRefresh callback harus return Promise<string> berisi token baru.
   */
  function _scheduleRefresh(expiresAt, onRefresh) {
    if (_state._refreshTimer) clearTimeout(_state._refreshTimer);
    if (!onRefresh || !expiresAt) return;

    const msUntilExpiry = expiresAt * 1000 - Date.now();
    // Refresh 5 menit sebelum expiry
    const refreshIn = Math.max(msUntilExpiry - 5 * 60 * 1000, 0);

    _state._refreshTimer = setTimeout(async () => {
      try {
        const newToken = await onRefresh();
        if (newToken) await _initWithToken(newToken, onRefresh);
      } catch (err) {
        console.warn("[KawanuaLicense] Auto-refresh gagal:", err.message);
      }
    }, refreshIn);
  }

  // ─── Core init ───────────────────────────────────────────────────

  async function _initWithToken(token, onRefresh) {
    // 1. Verify JWT
    const payload = await _verifyToken(token);

    // 2. Pastikan status aktif
    if (!payload.valid || payload.status !== "active") {
      throw new Error(
        "Lisensi tidak aktif. Silakan perpanjang atau hubungi dukungan.",
      );
    }

    // 3. Ambil plan dari payload
    const plan = payload.license?.plan ?? "starter";

    // 4. Resolve features (default plan + override dari JWT)
    const features = _resolveFeatures(plan, payload.features ?? {});

    // 5. Update state
    _state = {
      ..._state,
      initialized: true,
      valid: true,
      plan,
      features,
      license: payload.license ?? null,
      expiresAt: payload.exp ?? null,
    };

    // 6. Apply branding berdasarkan features
    _applyBranding(features);

    // 7. Schedule refresh otomatis
    _scheduleRefresh(payload.exp, onRefresh);

    return _state;
  }

  // ─── Public API ─────────────────────────────────────────────────

  const KawanuaLicense = {
    /**
     * Inisialisasi SDK dengan token JWT.
     *
     * @param {object} options
     * @param {string}   options.token     — JWT token dari server lisensi Kawanua
     * @param {Function} [options.onRefresh] — async () => string — callback untuk refresh token
     * @param {Function} [options.onReady]  — callback setelah init berhasil
     * @param {Function} [options.onError]  — callback jika init gagal
     *
     * @example
     * KawanuaLicense.init({
     *   token: 'eyJ...',
     *   onRefresh: async () => {
     *     const res = await fetch('/api/license/token');
     *     const { token } = await res.json();
     *     return token;
     *   },
     *   onReady: (state) => console.log('Plan:', state.plan),
     *   onError: (err) => console.error('Lisensi error:', err.message),
     * });
     */
    async init({ token, onRefresh, onReady, onError } = {}) {
      try {
        const state = await _initWithToken(token, onRefresh);
        onReady?.(state);
        return state;
      } catch (err) {
        _state.initialized = true;
        _state.valid = false;
        // Fallback: jika error, tampilkan branding (gagal safe)
        _applyBranding({ remove_branding: false });
        onError?.(err);
        throw err;
      }
    },

    /**
     * Cek apakah fitur tertentu aktif.
     * Harus dipanggil setelah init().
     *
     * @param {string} featureName — nama fitur sesuai PLAN_FEATURES
     * @returns {boolean|number|string}
     *
     * @example
     * if (KawanuaLicense.can('api_access')) {
     *   // tampilkan tombol API
     * }
     */
    can(featureName) {
      if (!_state.initialized) {
        console.warn(
          "[KawanuaLicense] SDK belum diinisialisasi. Panggil init() terlebih dahulu.",
        );
        return false;
      }
      return _state.features[featureName] ?? false;
    },

    /**
     * Dapatkan nilai numerik/string sebuah fitur.
     * Berguna untuk limit seperti max_users.
     *
     * @example
     * const maxUsers = KawanuaLicense.get('max_users'); // 5, 50, atau Infinity
     */
    get(featureName) {
      return _state.features[featureName] ?? null;
    },

    /**
     * Dapatkan plan aktif saat ini.
     * @returns {'starter'|'professional'|'enterprise'|null}
     */
    getPlan() {
      return _state.plan;
    },

    /**
     * Dapatkan full state (readonly snapshot).
     */
    getState() {
      return { ..._state, features: { ..._state.features } };
    },

    /**
     * Cek apakah lisensi valid dan aktif.
     */
    isValid() {
      return _state.initialized && _state.valid;
    },

    /**
     * Destroy: bersihkan timer, reset state.
     */
    destroy() {
      if (_state._refreshTimer) clearTimeout(_state._refreshTimer);
      _state = {
        initialized: false,
        valid: false,
        plan: null,
        features: {},
        license: null,
        expiresAt: null,
        _refreshTimer: null,
      };
    },
  };

  return KawanuaLicense;
});
