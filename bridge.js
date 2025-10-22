const TRACE_HEADER = 'X-Trace-Id';
const DEFAULT_TIMEOUT = 30000;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== '/v1/relay') {
      return j({ error: 'not_found' }, 404, trace());
    }
    if (request.method !== 'POST') {
      return j({ error: 'method_not_allowed' }, 405, trace());
    }

    const ts = request.headers.get('X-TS') || '';
    const kid = request.headers.get('X-KID') || '';
    const sig = request.headers.get('X-SIG') || '';
    const origin = request.headers.get('X-ORIGIN') || '';
    const traceId = request.headers.get(TRACE_HEADER) || trace();

    let body;
    try {
      body = await request.json();
    } catch {
      return j({ error: 'invalid_json' }, 400, traceId);
    }

    const now = Date.now();
    if (!ts || Math.abs(now - Number(ts)) > 120000) {
      return j({ error: 'stale' }, 401, traceId);
    }

    const provider = String(body.provider || '').toLowerCase();
    const lang = (body.lang || 'en').slice(0, 5);
    const message = norm(String(body.message || ''));
    const incomingAttachments = Array.isArray(body.attachments) ? body.attachments : [];

    const policy = await loadPolicy();
    if (!policy.allowedProviders.includes(provider)) {
      return j({ error: 'bad_provider' }, 400, traceId);
    }
    if (!message) {
      return j({ error: 'empty' }, 400, traceId);
    }
    if (message.length > policy.maxChars) {
      return j({ error: 'too_long' }, 400, traceId);
    }
    if (violates(message, policy.bannedPatterns)) {
      return j({ error: 'rejected' }, 400, traceId);
    }

    const sanitizedAttachments = sanitizeAttachments(incomingAttachments, policy);
    if (canon(incomingAttachments) !== canon(sanitizedAttachments)) {
      return j({ error: 'attachment_policy_violation' }, 400, traceId);
    }

    const canonicalAttachments = canon(sanitizedAttachments);
    const expect = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}.${canonicalAttachments}`);
    if (!tse(sig, expect)) {
      return j({ error: 'bad_sig' }, 401, traceId);
    }

    const registry = parseRegistry(env.PROVIDER_REGISTRY);
    const target = registry[provider];
    if (!target || !target.url) {
      ctx?.waitUntil(audit(env, { event: 'bridge.misroute', traceId, provider }));
      return j({ error: 'unconfigured_provider' }, 502, traceId);
    }

    const timeout = Number(target.timeoutMs) > 0 ? Number(target.timeoutMs) : DEFAULT_TIMEOUT;
    const method = (target.method || 'POST').toUpperCase();
    const headers = {
      'Content-Type': 'application/json',
      ...(target.headers || {})
    };

    const payload = {
      message,
      lang,
      attachments: sanitizedAttachments,
      metadata: {
        origin,
        kid,
        ts,
        traceId,
        policyVersion: policy.version || 1
      }
    };

    ctx?.waitUntil(
      audit(env, {
        event: 'bridge.forward',
        traceId,
        provider,
        target: target.url,
        attachmentCount: sanitizedAttachments.length
      })
    );

    let upstream;
    try {
      upstream = await withTimeout((signal) => fetch(target.url, {
        method,
        headers,
        body: JSON.stringify(payload),
        signal
      }), timeout);
    } catch (error) {
      ctx?.waitUntil(audit(env, {
        event: 'bridge.upstream_error',
        traceId,
        provider,
        message: error instanceof Error ? error.message : String(error)
      }));
      if (error?.name === 'AbortError' || error?.message === 'timeout' || error === 'timeout') {
        return j({ error: 'upstream_timeout' }, 504, traceId);
      }
      return j({ error: 'upstream_error' }, 502, traceId);
    }

    const data = await safeJson(upstream);
    if (!upstream.ok) {
      ctx?.waitUntil(audit(env, {
        event: 'bridge.upstream_failure',
        traceId,
        provider,
        status: upstream.status,
        response: data
      }));
      return j({ error: data.error || 'upstream_failure' }, upstream.status, traceId);
    }

    ctx?.waitUntil(audit(env, {
      event: 'bridge.success',
      traceId,
      provider,
      durationMs: Date.now() - now
    }));

    const text = typeof data.text === 'string'
      ? data.text
      : typeof data.output === 'string'
        ? data.output
        : JSON.stringify(data);

    return new Response(JSON.stringify({
      provider,
      model: data.model || null,
      text
    }), {
      status: 200,
      headers: strict(traceId)
    });
  }
};

/* ---------- helpers ---------- */
function j(obj, status = 200, traceId = trace()) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: strict(traceId)
  });
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

function violates(s, pats) {
  return pats.some((p) => new RegExp(p, 'g').test(s));
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(msg));
  return hex(new Uint8Array(sig));
}

function tse(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
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

function strict(traceId) {
  return {
    'Content-Type': 'application/json',
    [TRACE_HEADER]: traceId,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store'
  };
}

function trace() {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `tr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function parseRegistry(raw) {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === 'object' && parsed ? parsed : {};
  } catch {
    return {};
  }
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
    const size = Number(item.size) || base64Size(data);
    if (!name || !type || !data) continue;
    if (!isBase64(data)) continue;
    if (allowed.size && !allowed.has(type)) continue;
    if (!size || (maxBytes && (size > maxBytes || (total + size) > maxBytes))) continue;
    total += size;
    out.push({ name, type, data, size });
  }
  return out;
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
      body: JSON.stringify({ ...payload, service: 'bridge' })
    });
  } catch (err) {
    console.warn('audit_failed', err);
  }
}

async function withTimeout(fn, ms) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(new Error('timeout')), ms);
  try {
    return await fn(ctrl.signal);
  } finally {
    clearTimeout(id);
  }
}
