const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WEB_SERVER_PORT = parseInt(process.env.WEB_SERVER_PORT || process.env.PORT || '3000', 10) || 3000;
const DIST_DIR = path.resolve(__dirname, 'dist');
const DIST_INDEX_PATH = path.join(DIST_DIR, 'index.html');
const BOOTSTRAP_GLOBAL_NAME = '__SALAMA_BOOTSTRAP__';
const EDGE_CLIENT_TOKEN_SECRET = String(process.env.EDGE_CLIENT_TOKEN_SECRET || '0x4AAAAAAC9SNde9gUDyGp6U').trim();
const EDGE_PROOF_TOKEN_SECRET = String(process.env.EDGE_PROOF_TOKEN_SECRET ||  '0x4AAAAAAC9SNXfMob6pcPmEKh289ff76eo0x4AAAAAAC9SNde9gUDyGp6U').trim();
const EDGE_CLIENT_TOKEN_TTL_MS = Math.max(60 * 1000, parseInt(process.env.EDGE_CLIENT_TOKEN_TTL_MS || `${3 * 60 * 60 * 1000}`, 10) || 3 * 60 * 60 * 1000);
const EDGE_PROOF_COOKIE_NAME = '__Host-salama_etp';
const INIT_UPSTREAM_URL = String(process.env.INIT_UPSTREAM_URL || 'https://api-edge-proxy.mysemitgo.workers.dev').trim();
const WORKER_SHARED_SECRET = String(process.env.WORKER_SHARED_SECRET || 'TqD08hL6DBEeBoIULuZOx4kspDjPl3ft47g4').trim();
const WEB_GATEWAY_SECRET = String(process.env.WEB_GATEWAY_SECRET || '6LdvHr8sAAAAAPeLSJT30lpR2nm0nnUq6UT5LxK2').trim();
const TURNSTILE_SECRET = String(process.env.TURNSTILE_SECRET || '0x4AAAAAAC9SNXfMob6pcPmEKh289ff76eo').trim();
const TURNSTILE_TRUST_COOKIE_ENABLED =
  String(process.env.TURNSTILE_TRUST_COOKIE_ENABLED || 'false').toLowerCase() === 'true' ||
  String(process.env.TURNSTILE_TRUST_COOKIE_ENABLED || '').trim() === '1';
const TURNSTILE_TRUST_COOKIE_SECRET = String(process.env.TURNSTILE_TRUST_COOKIE_SECRET || TURNSTILE_SECRET || '').trim();
const TURNSTILE_TRUST_COOKIE_NAME = String(process.env.TURNSTILE_TRUST_COOKIE_NAME || '__Host-salama_ts').trim();
const TURNSTILE_TRUST_COOKIE_TTL_SEC = Math.max(30, parseInt(process.env.TURNSTILE_TRUST_COOKIE_TTL_SEC || '300', 10) || 300);
const TURNSTILE_TRUST_COOKIE_SECURE =
  String(process.env.TURNSTILE_TRUST_COOKIE_SECURE || (process.env.NODE_ENV === 'production' ? 'true' : 'false')).toLowerCase() === 'true' ||
  String(process.env.TURNSTILE_TRUST_COOKIE_SECURE || '').trim() === '1';
const TURNSTILE_MAX_AGE_SEC = Math.max(0, parseInt(process.env.TURNSTILE_MAX_AGE_SEC || '0', 10) || 0);
const TURNSTILE_ALLOWED_HOSTNAMES = new Set(
  String(process.env.TURNSTILE_ALLOWED_HOSTNAMES || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
);
const TURNSTILE_ALLOWED_ACTIONS = new Set(
  String(process.env.TURNSTILE_ALLOWED_ACTIONS || 'managed')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
);
const TURNSTILE_ENFORCE_ACTION =
  String(process.env.TURNSTILE_ENFORCE_ACTION || 'false').toLowerCase() === 'true' ||
  String(process.env.TURNSTILE_ENFORCE_ACTION || '').trim() === '1';
const RECAPTCHA_SECRET = String(process.env.RECAPTCHA_SECRET || process.env.GOOGLE_RECAPTCHA_SECRET || '6LencL8sAAAAABK68lD6ODE0DIRtTcnwNowcspuz').trim();
const RECAPTCHA_ENABLED =
  String(process.env.RECAPTCHA_ENABLED || 'true').toLowerCase() === 'true' ||
  String(process.env.RECAPTCHA_ENABLED || '').trim() === '1';
const RECAPTCHA_MIN_SCORE = Math.max(0, Math.min(1, Number.parseFloat(process.env.RECAPTCHA_MIN_SCORE || '0.3') || 0.3));
const RECAPTCHA_MAX_AGE_SEC = Math.max(30, parseInt(process.env.RECAPTCHA_MAX_AGE_SEC || '180', 10) || 180);
const RECAPTCHA_ALLOWED_HOSTNAMES = new Set(
  String(process.env.RECAPTCHA_ALLOWED_HOSTNAMES || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
);
const INIT_PAYLOAD_CACHE_TTL_MS = Math.max(10 * 1000, parseInt(process.env.INIT_PAYLOAD_CACHE_TTL_MS || '60000', 10) || 60000);
const INIT_RATE_LIMIT_FALLBACK_MS = Math.max(1000, parseInt(process.env.INIT_RATE_LIMIT_FALLBACK_MS || '5000', 10) || 5000);
const initPayloadCache = new Map();
const initRateLimitUntilByKey = new Map();

const app = express();
app.set('trust proxy', true);

const getRequestOrigin = (req) => {
  const origin = String(req.headers.origin || '').trim();
  if (origin) return origin;
  const protoHeader = String(req.headers['x-forwarded-proto'] || '').trim();
  const proto = protoHeader ? protoHeader.split(',')[0].trim() : req.protocol || 'http';
  const host = String(req.headers.host || '').trim();
  if (!host) return null;
  return `${proto}://${host}`;
};

const hmacSha256Hex = (secret, message) =>
  crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');

const sha256Hex = (value) =>
  crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');

const toBase64Url = (value) =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const fromBase64Url = (value) => {
  const b64 = String(value || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const padLen = (4 - (b64.length % 4)) % 4;
  return Buffer.from(b64 + '='.repeat(padLen), 'base64');
};

const escapeHtmlAttribute = (value) =>
  String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

const normalizeIp = (ip) => {
  const s0 = String(ip || '').trim();
  if (!s0) return '';
  const s = s0.split('%')[0];
  if (s.toLowerCase().startsWith('::ffff:')) return s.slice(7);
  if (s === '::1') return '127.0.0.1';
  return s;
};

const getClientIp = (req) => {
  const cf = String(req.headers['cf-connecting-ip'] || '').trim();
  if (cf) return normalizeIp(cf);
  const tci = String(req.headers['true-client-ip'] || '').trim();
  if (tci) return normalizeIp(tci);
  const xff = String(req.headers['x-forwarded-for'] || '').trim();
  if (xff) return normalizeIp(xff.split(',')[0].trim());
  return normalizeIp(req.socket?.remoteAddress || '');
};

const parseCookies = (req) => {
  const raw = String(req.headers.cookie || '').trim();
  if (!raw) return {};
  return raw.split(';').reduce((acc, chunk) => {
    const [k, ...rest] = chunk.split('=');
    const key = decodeURIComponent(String(k || '').trim());
    if (!key) return acc;
    const value = decodeURIComponent(rest.join('=').trim());
    acc[key] = value;
    return acc;
  }, {});
};

const getRequestBrowserInfo = (req) => {
  const ua = String(req.headers['user-agent'] || '');
  const acceptedLanguages = String(req.headers['accept-language'] || '')
    .split(',')
    .map((entry) => entry.split(';')[0].trim())
    .filter(Boolean);
  return {
    browser: 'Unknown',
    browserVersion: '',
    os: 'Unknown',
    device: /Mobile|Android|iPhone|iPad/i.test(ua) ? 'Mobile' : 'Desktop',
    userAgent: ua,
    language: acceptedLanguages[0] || 'en',
    languages: acceptedLanguages,
    platform: '',
    screenWidth: 0,
    screenHeight: 0,
    timezone: 'UTC',
  };
};

const createEdgeClientToken = (req, options = {}) => {
  if (!EDGE_CLIENT_TOKEN_SECRET) return null;
  const now = Date.now();
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 200);
  const tokenUuid = String(options.uuid || '').trim();
  const payload = {
    v: 1,
    iat: now,
    exp: now + EDGE_CLIENT_TOKEN_TTL_MS,
    jti: crypto.randomBytes(12).toString('hex'),
    uuid: tokenUuid || null,
    ip: normalizeIp(getClientIp(req)),
    uaHash: sha256Hex(userAgent),
    origin: getRequestOrigin(req) || null,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = hmacSha256Hex(EDGE_CLIENT_TOKEN_SECRET, encodedPayload);
  return `${encodedPayload}.${signature}`;
};

const createEdgeProofToken = (req, options = {}) => {
  if (!EDGE_PROOF_TOKEN_SECRET) return null;
  const now = Date.now();
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 200);
  const tokenUuid = String(options.uuid || '').trim();
  const payload = {
    v: 1,
    typ: 'edge-proof',
    iat: now,
    exp: now + EDGE_CLIENT_TOKEN_TTL_MS,
    jti: crypto.randomBytes(12).toString('hex'),
    uuid: tokenUuid || null,
    ip: normalizeIp(getClientIp(req)),
    uaHash: sha256Hex(userAgent),
    origin: getRequestOrigin(req) || null,
  };
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash('sha256').update(EDGE_PROOF_TOKEN_SECRET, 'utf8').digest();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${toBase64Url(iv)}.${toBase64Url(ciphertext)}.${toBase64Url(tag)}`;
};

const verifyEdgeProofToken = (req, token, options = {}) => {
  if (!EDGE_PROOF_TOKEN_SECRET) return false;
  const rawToken = String(token || '').trim();
  if (!rawToken) return false;
  const parts = rawToken.split('.');
  if (parts.length !== 3) return false;
  try {
    const iv = fromBase64Url(parts[0]);
    const ciphertext = fromBase64Url(parts[1]);
    const tag = fromBase64Url(parts[2]);
    if (iv.length !== 12 || tag.length !== 16 || !ciphertext.length) return false;

    const key = crypto.createHash('sha256').update(EDGE_PROOF_TOKEN_SECRET, 'utf8').digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const payload = JSON.parse(decrypted.toString('utf8'));

    const now = Date.now();
    const exp = Number(payload?.exp || 0);
    const iat = Number(payload?.iat || 0);
    if (!Number.isFinite(exp) || exp <= now) return false;
    if (Number.isFinite(iat) && iat > now + 30_000) return false;
    if (payload?.typ && payload.typ !== 'edge-proof') return false;

    const expectedIp = normalizeIp(getClientIp(req));
    const tokenIp = normalizeIp(String(payload?.ip || '').trim());
    if (!expectedIp || !tokenIp || expectedIp !== tokenIp) return false;

    const ua = String(req.headers['user-agent'] || '').slice(0, 200);
    const uaHash = String(payload?.uaHash || '').trim();
    if (!uaHash || uaHash !== sha256Hex(ua)) return false;

    const tokenOrigin = String(payload?.origin || '').trim();
    const reqOrigin = String(getRequestOrigin(req) || '').trim();
    if (tokenOrigin && reqOrigin && tokenOrigin !== reqOrigin) return false;

    const tokenUuid = String(payload?.uuid || '').trim();
    const expectedUuid = String(options?.expectedUuid || '').trim();
    if (tokenUuid && expectedUuid && tokenUuid !== expectedUuid) return false;
    if (tokenUuid && !expectedUuid) return false;

    return true;
  } catch {
    return false;
  }
};

const serializeBootstrapForHtml = (payload) =>
  JSON.stringify(payload)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

const injectBootstrapIntoHtml = (html, payload) => {
  const script = `<script>window.${BOOTSTRAP_GLOBAL_NAME}=${serializeBootstrapForHtml(payload)};</script>`;
  if (html.includes('</head>') && html.includes('</body>')) {
    const trapToken = String(payload?.edgeClientToken || '').trim();
    const trapHash = trapToken ? sha256Hex(trapToken) : '';
    const trapScatter = trapHash
      ? [
          `<div style="display:none" aria-hidden="true" data-analytics-id="${escapeHtmlAttribute(trapHash.slice(0, 12))}" data-build="${escapeHtmlAttribute(trapHash.slice(12, 24))}"></div>`,
          `<div style="display:none" aria-hidden="true" data-react-checksum="${escapeHtmlAttribute(trapHash.slice(24, 36))}"></div>`,
          `<div style="display:none" aria-hidden="true" data-client-hint="${escapeHtmlAttribute(trapHash.slice(36, 48))}" data-node-id="${escapeHtmlAttribute(trapHash.slice(48, 60))}"></div>`,
          `<!-- hydrate:${escapeHtmlAttribute(trapHash.slice(60, 64))}:${escapeHtmlAttribute(trapHash.slice(8, 16))} -->`,
        ].join('')
      : '';
    const withScript = html.replace('</head>', `${script}</head>`);
    return withScript.replace('</body>', `${trapScatter}</body>`);
  }
  if (html.includes('</body>')) {
    return html.replace('</body>', `${script}</body>`);
  }
  return `${html}${script}`;
};

const setEdgeProofCookie = (res, token) => {
  if (!token) return;
  const maxAgeSec = Math.max(60, Math.floor(EDGE_CLIENT_TOKEN_TTL_MS / 1000));
  res.append(
    'Set-Cookie',
    `${EDGE_PROOF_COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${maxAgeSec}; Path=/; HttpOnly; Secure; SameSite=None`
  );
};

const getEdgeProofCookie = (req) => {
  const cookies = parseCookies(req);
  return String(cookies[EDGE_PROOF_COOKIE_NAME] || '').trim();
};

const getExpectedUuidFromRequest = (req) => {
  const body = req && typeof req.body === 'object' && req.body ? req.body : {};
  const headerUuid = String(req.headers['x-user-uuid'] || '').trim();
  const bodyUuid = typeof body.uuid === 'string' ? body.uuid.trim() : '';
  if (headerUuid && bodyUuid && headerUuid !== bodyUuid) return null;
  return headerUuid || bodyUuid || '';
};

const getTurnstileTrustCookie = (req) => {
  const cookies = parseCookies(req);
  return String(cookies[TURNSTILE_TRUST_COOKIE_NAME] || '').trim();
};

const createTurnstileTrustCookieValue = (req) => {
  if (!TURNSTILE_TRUST_COOKIE_SECRET) return '';
  const now = Date.now();
  const ip = normalizeIp(getClientIp(req));
  const ua = String(req.headers['user-agent'] || '').slice(0, 200);
  const payload = {
    v: 1,
    iat: now,
    exp: now + TURNSTILE_TRUST_COOKIE_TTL_SEC * 1000,
    ipHash: sha256Hex(ip),
    uaHash: sha256Hex(ua),
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = hmacSha256Hex(TURNSTILE_TRUST_COOKIE_SECRET, encodedPayload);
  return `${encodedPayload}.${signature}`;
};

const verifyTurnstileTrustCookie = (req, rawToken) => {
  if (!TURNSTILE_TRUST_COOKIE_SECRET) return false;
  const token = String(rawToken || '').trim();
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [encodedPayload, signature] = parts;
  if (!encodedPayload || !signature) return false;
  const expectedSignature = hmacSha256Hex(TURNSTILE_TRUST_COOKIE_SECRET, encodedPayload);
  if (!expectedSignature || expectedSignature !== signature) return false;
  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    const now = Date.now();
    const exp = Number(payload?.exp || 0);
    const iat = Number(payload?.iat || 0);
    if (!Number.isFinite(exp) || exp <= now) return false;
    if (!Number.isFinite(iat) || iat > now + 30_000) return false;

    const ip = normalizeIp(getClientIp(req));
    const ua = String(req.headers['user-agent'] || '').slice(0, 200);
    const ipHash = String(payload?.ipHash || '').trim();
    const uaHash = String(payload?.uaHash || '').trim();
    if (!ipHash || ipHash !== sha256Hex(ip)) return false;
    if (!uaHash || uaHash !== sha256Hex(ua)) return false;
    return true;
  } catch {
    return false;
  }
};

const setTurnstileTrustCookie = (res, token) => {
  if (!token) return;
  res.append(
    'Set-Cookie',
    `${TURNSTILE_TRUST_COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${TURNSTILE_TRUST_COOKIE_TTL_SEC}; Path=/; HttpOnly; ${TURNSTILE_TRUST_COOKIE_SECURE ? 'Secure; ' : ''}SameSite=Lax`
  );
};

const extractTurnstileToken = (req) => {
  const fromHeaders =
    String(req.headers['cf-turnstile-response'] || '').trim() ||
    String(req.headers['cf-turnstile-token'] || '').trim() ||
    String(req.headers['x-turnstile-token'] || '').trim();
  if (fromHeaders) return fromHeaders;
  const body = req && typeof req.body === 'object' && req.body ? req.body : {};
  return String(body.turnstileToken || body['cf-turnstile-response'] || '').trim();
};

const extractRecaptchaToken = (req) => {
  const fromHeaders =
    String(req.headers['x-recaptcha-token'] || '').trim() ||
    String(req.headers['g-recaptcha-response'] || '').trim() ||
    String(req.headers['x-recaptcha-response'] || '').trim();
  if (fromHeaders) return fromHeaders;
  const body = req && typeof req.body === 'object' && req.body ? req.body : {};
  return String(body.recaptchaToken || body['g-recaptcha-response'] || '').trim();
};

const verifyTurnstileToken = async (req, token) => {
  if (!TURNSTILE_SECRET) return true;
  const normalizedToken = String(token || '').trim();
  if (!normalizedToken) return false;
  try {
    const body = new URLSearchParams();
    body.set('secret', TURNSTILE_SECRET);
    body.set('response', normalizedToken);
    const ip = getClientIp(req);
    if (ip && ip !== 'unknown') body.set('remoteip', ip);
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!response.ok) return false;
    const data = await response.json().catch(() => ({}));
    if (data.success !== true) {
      return false;
    }
    const hostname = String(data.hostname || '').trim().toLowerCase();
    if (TURNSTILE_ALLOWED_HOSTNAMES.size > 0 && (!hostname || !TURNSTILE_ALLOWED_HOSTNAMES.has(hostname))) return false;
    if (TURNSTILE_ENFORCE_ACTION) {
      const action = String(data.action || '').trim();
      if (!action || !TURNSTILE_ALLOWED_ACTIONS.has(action)) return false;
    }
    if (TURNSTILE_MAX_AGE_SEC > 0) {
      const ts = Date.parse(String(data.challenge_ts || '').trim());
      if (Number.isFinite(ts)) {
        const ageMs = Date.now() - ts;
        if (ageMs < -30_000 || ageMs > TURNSTILE_MAX_AGE_SEC * 1000) return false;
      }
    }
    return true;
  } catch {
    return false;
  }
};

const recaptchaExpectedActionForPath = (path) => {
  if (path === '/api/forms/booking') return 'booking_submit';
  if (path === '/api/forms/booking-update') return 'booking_update_submit';
  return null;
};

const verifyRecaptchaToken = async (req, token) => {
  if (!RECAPTCHA_ENABLED) return true;
  if (!RECAPTCHA_SECRET) return true;
  const normalizedToken = String(token || '').trim();
  if (!normalizedToken) return false;
  try {
    const body = new URLSearchParams();
    body.set('secret', RECAPTCHA_SECRET);
    body.set('response', normalizedToken);
    const ip = getClientIp(req);
    if (ip && ip !== 'unknown') body.set('remoteip', ip);
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!response.ok) return false;
    const data = await response.json().catch(() => ({}));
    if (data.success !== true) return false;
    const score = Number(data.score || 0);
    if (!Number.isFinite(score) || score < RECAPTCHA_MIN_SCORE) return false;
    const expectedAction = recaptchaExpectedActionForPath(req.path || req.originalUrl || '');
    if (expectedAction) {
      const action = String(data.action || '').trim();
      if (!action || action !== expectedAction) return false;
    }
    const hostname = String(data.hostname || '').trim().toLowerCase();
    if (RECAPTCHA_ALLOWED_HOSTNAMES.size > 0 && (!hostname || !RECAPTCHA_ALLOWED_HOSTNAMES.has(hostname))) return false;
    const ts = Date.parse(String(data.challenge_ts || '').trim());
    if (!Number.isFinite(ts)) return false;
    const ageMs = Date.now() - ts;
    if (ageMs < -30_000 || ageMs > RECAPTCHA_MAX_AGE_SEC * 1000) return false;
    return true;
  } catch {
    return false;
  }
};

const ensureGatewaySession = async (req, uuid) => {
  const normalizedUuid = String(uuid || '').trim();
  if (!normalizedUuid || !INIT_UPSTREAM_URL) return { ok: true, uuid: normalizedUuid };
  const requestOrigin = getRequestOrigin(req) || '';
  const ip = getClientIp(req) || '';
  const clientCountry = String(req.headers['cf-ipcountry'] || req.headers['x-client-country'] || '').trim().toUpperCase();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${INIT_UPSTREAM_URL.replace(/\/$/, '')}/api/userinit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': String(req.headers['user-agent'] || ''),
        Origin: requestOrigin,
        Referer: `${requestOrigin}/`,
        ...(ip ? { 'X-Forwarded-For': ip, 'X-Real-IP': ip } : {}),
        ...(clientCountry ? { 'X-Client-Country': clientCountry } : {}),
        ...(WORKER_SHARED_SECRET ? { 'X-Worker-Secret': WORKER_SHARED_SECRET } : {}),
        ...(WEB_GATEWAY_SECRET ? { 'X-Web-Gateway-Secret': WEB_GATEWAY_SECRET } : {}),
      },
      body: JSON.stringify({
        browserInfo: getRequestBrowserInfo(req),
        uuid: normalizedUuid,
      }),
      signal: controller.signal,
    });
    if (!response.ok) return { ok: false, uuid: normalizedUuid };
    const data = await response.json().catch(() => null);
    const resolvedUuid = String(data?.userInfo?.uuid || '').trim();
    return { ok: true, uuid: resolvedUuid || normalizedUuid };
  } catch {
    return { ok: false, uuid: normalizedUuid };
  } finally {
    clearTimeout(timeoutId);
  }
};

const resolvePreferredUuid = (req) => {
  const cookies = parseCookies(req);
  const fromUser = String(cookies.salama_user_uuid || '').trim();
  if (fromUser) return fromUser;
  const fromClient = String(cookies.salama_client_uuid_v1 || '').trim();
  if (fromClient) return fromClient;
  return '';
};

const parseRetryAfterMs = (retryAfterHeader) => {
  const raw = String(retryAfterHeader || '').trim();
  if (!raw) return 0;
  if (/^\d+$/.test(raw)) {
    return Math.max(0, Number(raw) * 1000);
  }
  const ts = Date.parse(raw);
  if (!Number.isFinite(ts)) return 0;
  return Math.max(0, ts - Date.now());
};

const getInitCacheKey = (req) => {
  const preferredUuid = resolvePreferredUuid(req);
  if (preferredUuid) return `uuid:${preferredUuid}`;
  const ip = getClientIp(req) || 'unknown';
  const ua = String(req.headers['user-agent'] || '').slice(0, 200);
  return `anon:${ip}:${sha256Hex(ua).slice(0, 24)}`;
};

const readInitPayloadCache = (cacheKey) => {
  const entry = initPayloadCache.get(cacheKey);
  if (!entry) return null;
  if (!entry.expiresAt || entry.expiresAt <= Date.now() || !entry.payload) {
    initPayloadCache.delete(cacheKey);
    return null;
  }
  return entry.payload;
};

const storeInitPayloadCache = (cacheKey, payload) => {
  if (!payload || typeof payload !== 'object') return;
  const now = Date.now();
  const entry = { payload, expiresAt: now + INIT_PAYLOAD_CACHE_TTL_MS };
  initPayloadCache.set(cacheKey, entry);
  const resolvedUuid = String(payload?.userInfo?.uuid || '').trim();
  if (resolvedUuid) {
    initPayloadCache.set(`uuid:${resolvedUuid}`, entry);
  }
};

const fetchInitPayload = async (req) => {
  if (!INIT_UPSTREAM_URL) return { payload: null, status: 503, retryAfterMs: 0 };
  try {
    const origin = getRequestOrigin(req) || '';
    const ip = getClientIp(req) || '';
    const clientCountry = String(req.headers['cf-ipcountry'] || req.headers['x-client-country'] || '').trim().toUpperCase();
    const uuid = resolvePreferredUuid(req);
    const body = JSON.stringify({
      browserInfo: getRequestBrowserInfo(req),
      uuid: uuid || undefined,
    });
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': String(req.headers['user-agent'] || ''),
      Origin: origin,
      Referer: `${origin}/`,
      'X-Forwarded-For': ip,
      'X-Real-IP': ip,
      ...(clientCountry ? { 'X-Client-Country': clientCountry } : {}),
      ...(WORKER_SHARED_SECRET ? { 'X-Worker-Secret': WORKER_SHARED_SECRET } : {}),
      ...(WEB_GATEWAY_SECRET ? { 'X-Web-Gateway-Secret': WEB_GATEWAY_SECRET } : {}),
    };
    const response = await fetch(`${INIT_UPSTREAM_URL.replace(/\/$/, '')}/api/userinit`, {
      method: 'POST',
      headers,
      body,
    });
    if (!response.ok) {
      const retryAfterMs = response.status === 429
        ? parseRetryAfterMs(response.headers.get('retry-after'))
        : 0;
      await response.text().catch(() => '');
      return { payload: null, status: response.status, retryAfterMs };
    }
    const data = await response.json();
    if (!data || typeof data !== 'object') {
      return { payload: null, status: 502, retryAfterMs: 0 };
    }
    if (!data?.userInfo || !data?.userInfo?.uuid) {
      return { payload: null, status: 502, retryAfterMs: 0 };
    }
    return { payload: data, status: 200, retryAfterMs: 0 };
  } catch (error) {
    return { payload: null, status: 502, retryAfterMs: 0 };
  }
};

const fetchInitPayloadWithRetry = async (req) => {
  const cacheKey = getInitCacheKey(req);
  const cachedPayload = readInitPayloadCache(cacheKey);
  if (cachedPayload) return cachedPayload;

  const blockedUntil = Number(initRateLimitUntilByKey.get(cacheKey) || 0);
  if (blockedUntil > Date.now()) {
    return null;
  }

  const attempts = 3;
  for (let i = 0; i < attempts; i += 1) {
    const { payload, status, retryAfterMs } = await fetchInitPayload(req);
    const uuid = String(payload?.userInfo?.uuid || '').trim();
    if (payload && uuid) {
      storeInitPayloadCache(cacheKey, payload);
      initRateLimitUntilByKey.delete(cacheKey);
      return payload;
    }
    if (status === 429) {
      const cooldownMs = Math.max(retryAfterMs || 0, INIT_RATE_LIMIT_FALLBACK_MS);
      initRateLimitUntilByKey.set(cacheKey, Date.now() + cooldownMs);
      break;
    }
    if (i < attempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, 250 * (i + 1)));
    }
  }
  return readInitPayloadCache(cacheKey);
};

const sendSpaDocument = async (req, res) => {
  if (!fs.existsSync(DIST_INDEX_PATH)) {
    res.status(503).type('text/plain').send('Frontend build not found. Run `npm run build` first.');
    return;
  }

  const initPayload = await fetchInitPayloadWithRetry(req);
  const resolvedUuid = String(initPayload?.userInfo?.uuid || '').trim();
  const fallbackUuid = String(resolvePreferredUuid(req) || '').trim();
  const effectiveUuid = resolvedUuid || fallbackUuid;
  const edgeClientToken = createEdgeClientToken(req, { uuid: effectiveUuid });
  const edgeProofToken = createEdgeProofToken(req, { uuid: effectiveUuid });
  const bootstrap = {
    ...(initPayload && typeof initPayload === 'object' ? initPayload : {}),
    ...(edgeClientToken ? { edgeClientToken } : {}),
  };
  const html = injectBootstrapIntoHtml(fs.readFileSync(DIST_INDEX_PATH, 'utf8'), bootstrap);
  setEdgeProofCookie(res, edgeProofToken);
  res
    .set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      Pragma: 'no-cache',
      Expires: '0',
    })
    .type('html')
    .send(html);
};

app.use(express.static(DIST_DIR, {
  index: false,
  setHeaders: (res, filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.html') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      return;
    }
    res.setHeader('Cache-Control', 'public, max-age=3600');
  },
}));

app.use(express.json({ limit: '512kb' }));

app.post(/^\/api\/forms(\/|$)/, async (req, res) => {
  if (!INIT_UPSTREAM_URL) {
    return res.status(503).json({ error: 'gateway_unavailable' });
  }

  const expectedUuid = getExpectedUuidFromRequest(req);
  if (expectedUuid === null) {
    return res.status(400).json({ error: 'uuid_mismatch', message: 'UUID mismatch between header and body.' });
  }

  let forwardedUuid = expectedUuid;
  if (expectedUuid) {
    const ensured = await ensureGatewaySession(req, expectedUuid);
    if (ensured.ok && ensured.uuid) {
      forwardedUuid = ensured.uuid;
    }
  }

  const upstreamBody =
    req && typeof req.body === 'object' && req.body
      ? { ...req.body }
      : {};
  if (forwardedUuid) {
    upstreamBody.uuid = forwardedUuid;
  }

  let turnstileTrusted = false;
  if (TURNSTILE_TRUST_COOKIE_ENABLED) {
    turnstileTrusted = verifyTurnstileTrustCookie(req, getTurnstileTrustCookie(req));
  }

  if (!turnstileTrusted) {
    const turnstileOk = await verifyTurnstileToken(req, extractTurnstileToken(req));
    if (!turnstileOk) {
      return res.status(403).json({ error: 'turnstile_required' });
    }
    if (TURNSTILE_TRUST_COOKIE_ENABLED) {
      const trustToken = createTurnstileTrustCookieValue(req);
      setTurnstileTrustCookie(res, trustToken);
    }
  }

  const recaptchaExpectedAction = recaptchaExpectedActionForPath(req.path || req.originalUrl || '');
  if (RECAPTCHA_ENABLED && recaptchaExpectedAction) {
    const recaptchaOk = await verifyRecaptchaToken(req, extractRecaptchaToken(req));
    if (!recaptchaOk) {
      return res.status(403).json({ error: 'recaptcha_required' });
    }
  }

  const targetUrl = `${INIT_UPSTREAM_URL.replace(/\/$/, '')}${req.originalUrl}`;
  const requestOrigin = getRequestOrigin(req) || '';
  const ip = getClientIp(req) || '';
  const clientCountry = String(req.headers['cf-ipcountry'] || req.headers['x-client-country'] || '').trim().toUpperCase();
  const turnstileHeader = String(req.headers['cf-turnstile-response'] || '').trim();
  const turnstileTokenHeader = String(req.headers['cf-turnstile-token'] || '').trim();
  const xTurnstileTokenHeader = String(req.headers['x-turnstile-token'] || '').trim();
  const recaptchaHeader = String(req.headers['x-recaptcha-token'] || '').trim();
  const recaptchaResponseHeader = String(req.headers['g-recaptcha-response'] || '').trim();
  const xRecaptchaResponseHeader = String(req.headers['x-recaptcha-response'] || '').trim();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12_000);
  try {
    const upstream = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': String(req.headers['user-agent'] || ''),
        Origin: requestOrigin,
        Referer: `${requestOrigin}/`,
        ...(ip ? { 'X-Forwarded-For': ip, 'X-Real-IP': ip } : {}),
        ...(clientCountry ? { 'X-Client-Country': clientCountry } : {}),
        ...(turnstileHeader ? { 'cf-turnstile-response': turnstileHeader } : {}),
        ...(turnstileTokenHeader ? { 'CF-Turnstile-Token': turnstileTokenHeader } : {}),
        ...(xTurnstileTokenHeader ? { 'X-Turnstile-Token': xTurnstileTokenHeader } : {}),
        ...(recaptchaHeader ? { 'X-Recaptcha-Token': recaptchaHeader } : {}),
        ...(recaptchaResponseHeader ? { 'g-recaptcha-response': recaptchaResponseHeader } : {}),
        ...(xRecaptchaResponseHeader ? { 'X-Recaptcha-Response': xRecaptchaResponseHeader } : {}),
        ...(forwardedUuid ? { 'X-User-UUID': forwardedUuid } : {}),
        ...(WORKER_SHARED_SECRET ? { 'X-Worker-Secret': WORKER_SHARED_SECRET } : {}),
        ...(WEB_GATEWAY_SECRET ? { 'X-Web-Gateway-Secret': WEB_GATEWAY_SECRET } : {}),
      },
      body: JSON.stringify(upstreamBody),
      signal: controller.signal,
    });

    const text = await upstream.text();
    res.status(upstream.status);
    const contentType = upstream.headers.get('content-type');
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    } else {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    }
    return res.send(text);
  } catch {
    return res.status(502).json({ error: 'gateway_forward_failed' });
  } finally {
    clearTimeout(timeoutId);
  }
});

app.use((req, res, next) => {
  if (path.extname(req.path)) {
    res.status(404).type('text/plain').send('Not found');
    return;
  }
  next();
});

app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    next();
    return;
  }
  res.status(405).type('text/plain').send('Method not allowed');
});

app.get('/__edge-token', (req, res) => {
  const trapToken = createEdgeClientToken(req);
  const proofToken = createEdgeProofToken(req, { uuid: resolvePreferredUuid(req) });
  if (!trapToken) {
    return res.status(503).json({ error: 'edge_token_unavailable' });
  }
  setEdgeProofCookie(res, proofToken);
  return res
    .set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      Pragma: 'no-cache',
      Expires: '0',
    })
    .json({ token: trapToken });
});

app.get(/.*/, async (_req, res) => {
  await sendSpaDocument(_req, res);
});

app.listen(WEB_SERVER_PORT);
