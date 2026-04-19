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

const resolvePreferredUuid = (req) => {
  const cookies = parseCookies(req);
  const fromUser = String(cookies.salama_user_uuid || '').trim();
  if (fromUser) return fromUser;
  const fromClient = String(cookies.salama_client_uuid_v1 || '').trim();
  if (fromClient) return fromClient;
  return '';
};

const fetchInitPayload = async (req) => {
  if (!INIT_UPSTREAM_URL) return null;
  try {
    const origin = getRequestOrigin(req) || '';
    const ip = getClientIp(req) || '';
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
      ...(WORKER_SHARED_SECRET ? { 'X-Worker-Secret': WORKER_SHARED_SECRET } : {}),
    };
    const response = await fetch(`${INIT_UPSTREAM_URL.replace(/\/$/, '')}/api/userinit`, {
      method: 'POST',
      headers,
      body,
    });
    if (!response.ok) return null;
    const data = await response.json();
    if (!data || typeof data !== 'object') return null;
    return data;
  } catch {
    return null;
  }
};

const sendSpaDocument = async (req, res) => {
  if (!fs.existsSync(DIST_INDEX_PATH)) {
    res.status(503).type('text/plain').send('Frontend build not found. Run `npm run build` first.');
    return;
  }

  const initPayload = await fetchInitPayload(req);
  const resolvedUuid = String(initPayload?.userInfo?.uuid || '').trim();
  const edgeClientToken = createEdgeClientToken(req, { uuid: resolvedUuid });
  const edgeProofToken = createEdgeProofToken(req, { uuid: resolvedUuid });
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

  const proofCookie = getEdgeProofCookie(req);
  const proofOk = verifyEdgeProofToken(req, proofCookie, { expectedUuid });
  if (!proofOk) {
    return res.status(403).json({
      error: 'edge_proof_required',
      message: 'Missing or invalid encrypted edge proof token',
    });
  }

  const targetUrl = `${INIT_UPSTREAM_URL.replace(/\/$/, '')}${req.originalUrl}`;
  const requestOrigin = getRequestOrigin(req) || '';
  const ip = getClientIp(req) || '';
  const clientCountry = String(req.headers['cf-ipcountry'] || req.headers['x-client-country'] || '').trim().toUpperCase();
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
        ...(WORKER_SHARED_SECRET ? { 'X-Worker-Secret': WORKER_SHARED_SECRET } : {}),
        ...(WEB_GATEWAY_SECRET ? { 'X-Web-Gateway-Secret': WEB_GATEWAY_SECRET } : {}),
      },
      body: JSON.stringify(req.body || {}),
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

app.listen(WEB_SERVER_PORT, () => {
  console.log(`Web server listening on ${WEB_SERVER_PORT}`);
});
