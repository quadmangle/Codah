export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/v1/gateway') {
      return j({ error: 'not_found' }, 404);
    }

    // --- Strict Origin / CORS
    const origin = request.headers.get('Origin') || '';
    const allow = parseCsv(env.ALLOWED_ORIGINS || '');
    const corsOk = !!origin && allow.includes(origin);
    if (!corsOk) return j({ error: 'origin_blocked' }, 403, corsHdr(origin, false));

    // --- Content-Type must be JSON
    const ctype = (request.headers.get('Content-Type') || '').toLowerCase();
    if (!ctype.startsWith('application/json')) {
      return j({ error: 'bad_content_type' }, 415, corsHdr(origin, true));
    }

    // --- Basic header bot checks
    const ua = request.headers.get('User-Agent') || '';
    const sfs = (request.headers.get('Sec-Fetch-Site') || '').toLowerCase();
    const ref = request.headers.get('Referer') || '';
    const ip  = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    const policy = await loadPolicy();
    if (matchesAny(ua, policy.denyUserAgents)) {
      return j({ error: 'ua_denied' }, 403, corsHdr(origin, true));
    }
    if (sfs === 'cross-site') {
      return j({ error: 'cross_site_blocked' }, 403, corsHdr(origin, true));
    }

    // --- Parse body
    let body;
    try { body = await request.json(); } catch { return j({ error:'invalid_json' }, 400, corsHdr(origin, true)); }

    const provider = String(body.provider || '').toLowerCase();
    let message = norm(String(body.message || ''));
    const lang = (body.lang || 'en').slice(0, 5);
    const honeypot = String(body.honeypot || '');

    // --- Honeypot
    if (honeypot) return j({ error: 'blocked' }, 403, corsHdr(origin, true));

    // --- Provider allowlist
    if (!policy.allowedProviders.includes(provider)) {
      return j({ error:'bad_provider' }, 400, corsHdr(origin, true));
    }

    // --- Length & pattern scan
    if (!message) return j({ error:'empty' }, 400, corsHdr(origin, true));
    if (message.length > policy.maxChars) message = message.slice(0, policy.maxChars);
    if (violates(message, policy.bannedPatterns)) {
      return j({ error:'rejected' }, 400, corsHdr(origin, true));
    }

    // --- Minimal IP pacing (no KV): enforce min interval per IP
    const now = Date.now();
    const stampKey = `rl:${ip}`;
    const cached = await caches.default.match(new Request(`https://cache/${stampKey}`));
    if (cached) {
      const last = Number(await cached.text());
      if ((now - last) < policy.minIntervalMs) {
        return j({ error:'rate_limited' }, 429, corsHdr(origin, true));
      }
    }
    await caches.default.put(
      new Request(`https://cache/${stampKey}`),
      new Response(String(now), { headers: { 'Cache-Control': 'max-age=5' }})
    );

    // --- Create signed envelope for Bridge
    const ts = String(now);
    const kid = 'kid-' + now.toString(36) + '-' + Math.random().toString(36).slice(2, 8);
    const envelope = { provider, lang, message, ts, kid, origin, ref };

    const sig = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}`);
    const bridgeUrl = (env.BRIDGE_URL || '').replace(/\/+$/,'') + '/v1/relay';

    const out = await fetch(bridgeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-KID': kid,
        'X-TS': ts,
        'X-SIG': sig,
        'X-ORIGIN': origin
      },
      body: JSON.stringify(envelope)
    });

    const data = await safeJson(out);
    if (!out.ok) return j({ error: data.error || 'bridge_error' }, out.status, corsHdr(origin, true));

    return j({
      provider: data.provider || provider,
      model: data.model || null,
      text: typeof data.text === 'string' ? data.text : JSON.stringify(data)
    }, 200, corsHdr(origin, true, true));
  }
};

/* ---------- helpers ---------- */
function parseCsv(s){ return s.split(',').map(x=>x.trim()).filter(Boolean); }
function matchesAny(s, pats){ return pats.some(p => new RegExp(p).test(s)); }
function violates(s, pats){ return pats.some(p => new RegExp(p,'g').test(s)); }
function norm(s){
  return s.normalize('NFKC')
    .replace(/\u0000/g,'')
    .replace(/[ \t]+/g,' ')
    .replace(/[\u2028\u2029]/g,' ')
    .trim();
}
async function loadPolicy(){
  return JSON.parse(await (await fetch(new URL('./policy.json', import.meta.url))).text());
}
async function hmac(secret, msg){
  const key = await crypto.subtle.importKey('raw', enc(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(msg));
  return hex(new Uint8Array(sig));
}
function enc(s){ return new TextEncoder().encode(s); }
function hex(a){ return [...a].map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function safeJson(res){ try{ return await res.json(); } catch{ return {}; } }
function j(obj, status=200, extra={}){
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type':'application/json', ...extra }
  });
}
function corsHdr(origin, allow, expose=false){
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Origin': allow ? origin : 'null',
    'Access-Control-Allow-Headers': 'content-type,x-client-nonce',
    'Access-Control-Allow-Methods': 'POST',
    'Access-Control-Max-Age': '600',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  };
  if (expose) h['Access-Control-Expose-Headers'] = 'content-type';
  return h;
}

