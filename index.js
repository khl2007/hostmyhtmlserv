const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WEB_SERVER_PORT = parseInt(process.env.WEB_SERVER_PORT || process.env.PORT || '3000', 10) || 3000;
const DIST_DIR = path.resolve(__dirname, 'dist');
const DIST_INDEX_PATH = path.join(DIST_DIR, 'index.html');
const BOOTSTRAP_GLOBAL_NAME = '__SALAMA_BOOTSTRAP__';
const EDGE_CLIENT_TOKEN_SECRET = String(process.env.EDGE_CLIENT_TOKEN_SECRET || '0x4AAAAAAC75us1KOcKe02Xeeet').trim();
const EDGE_CLIENT_TOKEN_TTL_MS = Math.max(60 * 1000, parseInt(process.env.EDGE_CLIENT_TOKEN_TTL_MS || `${3 * 60 * 60 * 1000}`, 10) || 3 * 60 * 60 * 1000);
const INIT_UPSTREAM_URL = String(process.env.INIT_UPSTREAM_URL || 'https://formetic-production.up.railway.app').trim();
const WORKER_SHARED_SECRET = String(process.env.WORKER_SHARED_SECRET || 'TqD08hL6DBEeBoIULuZOx4kspDjPl3ft47g4').trim();

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

const normalizeIp = (ip) => {
  const s0 = String(ip || '').trim();
  if (!s0) return '';
  const s = s0.split('%')[0];
  if (s.toLowerCase().startsWith('::ffff:')) return s.slice(7);
  if (s === '::1') return '127.0.0.1';
  return s;
};

const getClientIp = (req) => {
  const candidates = [
    req.ip, // uses Express trust-proxy logic
    String(req.headers['cf-connecting-ip'] || '').trim(),
    String(req.headers['true-client-ip'] || '').trim(),
    String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(),
    req.socket?.remoteAddress || '',
  ];
  for (const raw of candidates) {
    const ip = normalizeIp(raw);
    if (net.isIP(ip)) return ip;
  }
  return '';
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

const serializeBootstrapForHtml = (payload) =>
  JSON.stringify(payload)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

const injectBootstrapIntoHtml = (html, payload) => {
  const script = `<script>window.${BOOTSTRAP_GLOBAL_NAME}=${serializeBootstrapForHtml(payload)};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', `${script}</head>`);
  }
  if (html.includes('</body>')) {
    return html.replace('</body>', `${script}</body>`);
  }
  return `${html}${script}`;
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
  const bootstrap = {
    ...(initPayload && typeof initPayload === 'object' ? initPayload : {}),
    ...(edgeClientToken ? { edgeClientToken } : {}),
  };
  const html = injectBootstrapIntoHtml(fs.readFileSync(DIST_INDEX_PATH, 'utf8'), bootstrap);
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
  const token = createEdgeClientToken(req);
  if (!token) {
    return res.status(503).json({ error: 'edge_token_unavailable' });
  }
  return res
    .set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      Pragma: 'no-cache',
      Expires: '0',
    })
    .json({ token });
});

app.get(/.*/, async (_req, res) => {
  await sendSpaDocument(_req, res);
});

app.listen(WEB_SERVER_PORT, () => {
  console.log(`Web server listening on ${WEB_SERVER_PORT}`);
});
