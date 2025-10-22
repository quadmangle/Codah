const TRACE_HEADER = 'X-Trace-Id';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== '/v1/gateway') {
      return j({ error: 'not_found' }, 404, {}, trace());
    }

    const origin = request.headers.get('Origin') || '';
    const allow = parseCsv(env.ALLOWED_ORIGINS || '');
    const traceId = request.headers.get(TRACE_HEADER) || trace();

    if (request.method === 'OPTIONS') {
      const permitted = !!origin && allow.includes(origin);
      return new Response(null, { status: permitted ? 204 : 403, headers: corsHdr(origin, permitted, false, traceId) });
    }

    if (request.method !== 'POST') {
      return j({ error: 'method_not_allowed' }, 405, corsHdr(origin, false, false, traceId), traceId);
    }

    const policy = await loadPolicy();

    const corsOk = !!origin && allow.includes(origin);
    if (!corsOk) {
      ctx?.waitUntil(audit(env, {
        event: 'gateway.cors_block',
        traceId,
        origin,
        ip: request.headers.get('CF-Connecting-IP') || '0.0.0.0'
      }));
      return j({ error: 'origin_blocked' }, 403, corsHdr(origin, false, false, traceId), traceId);
    }

    const ctype = (request.headers.get('Content-Type') || '').toLowerCase();
    if (!ctype.startsWith('application/json')) {
      return j({ error: 'bad_content_type' }, 415, corsHdr(origin, true, false, traceId), traceId);
    }

    const ua = request.headers.get('User-Agent') || '';
    const sfs = (request.headers.get('Sec-Fetch-Site') || '').toLowerCase();
    const ref = request.headers.get('Referer') || '';
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    if (matchesAny(ua, policy.denyUserAgents)) {
      ctx?.waitUntil(audit(env, { event: 'gateway.ua_denied', traceId, ua, ip }));
      return j({ error: 'ua_denied' }, 403, corsHdr(origin, true, false, traceId), traceId);
    }
    if (sfs === 'cross-site') {
      ctx?.waitUntil(audit(env, { event: 'gateway.cross_site_blocked', traceId, ref, ip }));
      return j({ error: 'cross_site_blocked' }, 403, corsHdr(origin, true, false, traceId), traceId);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return j({ error: 'invalid_json' }, 400, corsHdr(origin, true, false, traceId), traceId);
    }

    const provider = String(body.provider || '').toLowerCase();
    let message = norm(String(body.message || ''));
    const lang = (body.lang || 'en').slice(0, 5);
    const honeypot = String(body.honeypot || '');
    const attachments = sanitizeAttachments(body.attachments, policy);

    if (honeypot) {
      ctx?.waitUntil(audit(env, { event: 'gateway.honeypot', traceId, ip }));
      return j({ error: 'blocked' }, 403, corsHdr(origin, true, false, traceId), traceId);
    }

    if (!policy.allowedProviders.includes(provider)) {
      return j({ error: 'bad_provider' }, 400, corsHdr(origin, true, false, traceId), traceId);
    }

    if (!message) {
      return j({ error: 'empty' }, 400, corsHdr(origin, true, false, traceId), traceId);
    }
    if (message.length > policy.maxChars) {
      message = message.slice(0, policy.maxChars);
    }
    if (violates(message, policy.bannedPatterns)) {
      return j({ error: 'rejected' }, 400, corsHdr(origin, true, false, traceId), traceId);
    }

    if (!validateAttachmentBudget(body.attachments, attachments, policy)) {
      return j({ error: 'attachment_policy_violation' }, 400, corsHdr(origin, true, false, traceId), traceId);
    }

    const now = Date.now();
    const stampKey = `rl:${ip}`;
    const cached = await caches.default.match(new Request(`https://cache/${stampKey}`));
    if (cached) {
      const last = Number(await cached.text());
      if (!Number.isNaN(last) && (now - last) < policy.minIntervalMs) {
        return j({ error: 'rate_limited' }, 429, corsHdr(origin, true, false, traceId), traceId);
      }
    }
    const ttlSeconds = Math.max(1, Math.ceil(policy.minIntervalMs / 1000));
    await caches.default.put(
      new Request(`https://cache/${stampKey}`),
      new Response(String(now), {
        headers: { 'Cache-Control': `max-age=${ttlSeconds}` }
      })
    );

    const ts = String(now);
    const kid = `kid-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const canonicalAttachments = canon(attachments);
    const sig = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}.${canonicalAttachments}`);
    const bridgeUrl = `${(env.BRIDGE_URL || '').replace(/\/+$/, '')}/v1/relay`;

    const envelope = {
      provider,
      lang,
      message,
      ts,
      kid,
      origin,
      ref,
      traceId,
      attachments
    };

    ctx?.waitUntil(audit(env, {
      event: 'gateway.forward',
      traceId,
      ip,
      provider,
      attachmentCount: attachments.length
    }));

    const out = await fetch(bridgeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-KID': kid,
        'X-TS': ts,
        'X-SIG': sig,
        'X-ORIGIN': origin,
        [TRACE_HEADER]: traceId
      },
      body: JSON.stringify(envelope)
    });

    const data = await safeJson(out);
    if (!out.ok) {
      ctx?.waitUntil(audit(env, {
        event: 'gateway.bridge_error',
        traceId,
        status: out.status,
        provider,
        response: data
      }));
      return j({ error: data.error || 'bridge_error' }, out.status, corsHdr(origin, true, false, traceId), traceId);
    }

    ctx?.waitUntil(audit(env, {
      event: 'gateway.success',
      traceId,
      provider,
      durationMs: Date.now() - now
    }));

    return j({
      provider: data.provider || provider,
      model: data.model || null,
      text: typeof data.text === 'string' ? data.text : JSON.stringify(data)
    }, 200, corsHdr(origin, true, true, traceId), traceId);
  }
};

/* ---------- helpers ---------- */
function parseCsv(s) {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

function matchesAny(s, pats) {
  return pats.some((p) => new RegExp(p).test(s));
}

function violates(s, pats) {
  return pats.some((p) => new RegExp(p, 'g').test(s));
}

function norm(s) {
  return s
    .normalize('NFKC')
    .replace(/\u0000/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/[\u2028\u2029]/g, ' ')
    .trim();
}

async function loadPolicy() {
  return JSON.parse(await (await fetch(new URL('./policy.json', import.meta.url))).text());
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(msg));
  return hex(new Uint8Array(sig));
}

function enc(s) {
  return new TextEncoder().encode(s);
}

function hex(a) {
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

function j(obj, status = 200, extra = {}, traceId = trace()) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json',
      [TRACE_HEADER]: traceId,
      ...extra
    }
  });
}

function corsHdr(origin, allow, expose = false, traceId) {
  const headers = {
    Vary: 'Origin',
    'Access-Control-Allow-Origin': allow ? origin : 'null',
    'Access-Control-Allow-Headers': 'content-type,x-client-nonce,x-trace-id',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Max-Age': '600',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(),camera=()'
  };
  if (expose) headers['Access-Control-Expose-Headers'] = 'content-type,' + TRACE_HEADER.toLowerCase();
  headers[TRACE_HEADER] = traceId;
  return headers;
}

function trace() {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `tr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function sanitizeAttachments(raw, policy) {
  if (!Array.isArray(raw) || !policy.maxAttachments) return [];
  const allowed = new Set(policy.allowedAttachmentTypes || []);
  const maxCount = Math.max(0, policy.maxAttachments | 0);
  const maxBytes = Math.max(0, policy.maxAttachmentBytes | 0);
  const out = [];
  let total = 0;
  for (const item of raw.slice(0, maxCount)) {
    if (!item || typeof item !== 'object') continue;
    const name = normFilename(String(item.name || '').slice(0, 128));
    const type = String(item.type || '').toLowerCase();
    const data = String(item.data || '');
    if (!name || !type || !data) continue;
    if (allowed.size && !allowed.has(type)) continue;
    if (!isBase64(data)) continue;
    const size = base64Size(data);
    if (!size) continue;
    if (maxBytes && (size > maxBytes || (total + size) > maxBytes)) continue;
    total += size;
    out.push({ name, type, data, size });
  }
  return out;
}

function validateAttachmentBudget(raw, sanitized, policy) {
  if (!Array.isArray(raw) && sanitized.length === 0) return true;
  if (!Array.isArray(raw)) return false;
  if (raw.length !== sanitized.length) return false;
  const canonicalIncoming = canon(raw);
  const canonicalSanitized = canon(sanitized);
  if (canonicalIncoming !== canonicalSanitized) return false;
  if (sanitized.length > (policy.maxAttachments || 0)) return false;
  const totalSize = sanitized.reduce((sum, item) => sum + (item.size || 0), 0);
  if (policy.maxAttachmentBytes && totalSize > policy.maxAttachmentBytes) return false;
  return true;
}

function canon(items) {
  if (!Array.isArray(items)) return '[]';
  return JSON.stringify(items.map((item) => ({
    name: item.name || '',
    type: item.type || '',
    data: item.data || '',
    size: item.size || 0
  })));
}

function normFilename(name) {
  return name
    .replace(/[^\w.\-\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function isBase64(value) {
  return /^[A-Za-z0-9+/=]+$/.test(value);
}

function base64Size(value) {
  const len = value.length;
  if (!len || len % 4 !== 0) return 0;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return Math.floor(len * 0.75) - padding;
}

async function audit(env, payload) {
  try {
    console.log(JSON.stringify(payload));
    const url = env?.AUDIT_WEBHOOK;
    if (!url) return;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, service: 'gateway' })
    });
  } catch (err) {
    console.warn('audit_failed', err);
  }
}
