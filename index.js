const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WEB_SERVER_PORT = parseInt(process.env.WEB_SERVER_PORT || process.env.PORT || '3000', 10) || 3000;
const DIST_DIR = path.resolve(__dirname, 'dist');
const DIST_INDEX_PATH = path.join(DIST_DIR, 'index.html');
const BOOTSTRAP_GLOBAL_NAME = '__SALAMA_BOOTSTRAP__';
const INIT_TOKEN_SECRET = process.env.INIT_TOKEN_SECRET || process.env.HMAC_SECRET || process.env.VITE_HMAC_SECRET || 'kn504yhdsdsdew546dsd';
const INIT_TOKEN_TTL_MS = 30 * 1000;
const EDGE_CLIENT_TOKEN_SECRET = String(process.env.EDGE_CLIENT_TOKEN_SECRET || process.env.INIT_TOKEN_SECRET || '0x4AAAAAAC9SNde9gUDyGp6U').trim();
const EDGE_CLIENT_TOKEN_TTL_MS = Math.max(60 * 1000, parseInt(process.env.EDGE_CLIENT_TOKEN_TTL_MS || `${3 * 60 * 60 * 1000}`, 10) || 3 * 60 * 60 * 1000);

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
  const cf = String(req.headers['cf-connecting-ip'] || '').trim();
  if (cf) return normalizeIp(cf);
  const tci = String(req.headers['true-client-ip'] || '').trim();
  if (tci) return normalizeIp(tci);
  const xff = String(req.headers['x-forwarded-for'] || '').trim();
  if (xff) return normalizeIp(xff.split(',')[0].trim());
  return normalizeIp(req.socket?.remoteAddress || '');
};

const computeIpPrefix = (ip) => {
  const normalized = normalizeIp(ip);
  if (!normalized) return '';
  // IPv4 /24 prefix.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(normalized)) {
    const parts = normalized.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  // IPv6 /56-ish coarse prefix (first 4 hextets).
  if (normalized.includes(':')) {
    const segs = normalized.split(':').filter(Boolean);
    const first = segs.slice(0, 4).join(':');
    return `${first}::/56`;
  }
  return normalized;
};

const createInitToken = (req) => {
  if (!INIT_TOKEN_SECRET) return null;
  const payload = {
    exp: Date.now() + INIT_TOKEN_TTL_MS,
    nonce: crypto.randomBytes(12).toString('hex'),
    origin: getRequestOrigin(req) || null,
    ua: String(req.headers['user-agent'] || '').slice(0, 200),
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = hmacSha256Hex(INIT_TOKEN_SECRET, encodedPayload);
  return `${encodedPayload}.${signature}`;
};

const createEdgeClientToken = (req) => {
  if (!EDGE_CLIENT_TOKEN_SECRET) return null;
  const now = Date.now();
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 200);
  const payload = {
    v: 1,
    iat: now,
    exp: now + EDGE_CLIENT_TOKEN_TTL_MS,
    jti: crypto.randomBytes(12).toString('hex'),
    ipPrefix: computeIpPrefix(getClientIp(req)),
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

const sendSpaDocument = (req, res) => {
  if (!fs.existsSync(DIST_INDEX_PATH)) {
    res.status(503).type('text/plain').send('Frontend build not found. Run `npm run build` first.');
    return;
  }

  const initToken = createInitToken(req);
  const edgeClientToken = createEdgeClientToken(req);
  const bootstrap = {
    ...(initToken ? { initToken } : {}),
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

app.get(/.*/, (_req, res) => {
  sendSpaDocument(_req, res);
});

app.listen(WEB_SERVER_PORT, () => {
  console.log(`Web server listening on ${WEB_SERVER_PORT}`);
});
