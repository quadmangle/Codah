export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/v1/gateway') {
      return json({ error: 'Not found' }, 404);
    }

    // Policy
    const policy = await loadPolicy(env);

    // Basic parse & shape
    let body;
    try { body = await request.json(); } catch { return json({ error:'invalid json' }, 400); }
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    const now = Date.now();

    // Validate fields
    const provider = String(body.provider || '').toLowerCase();
    const lang = (body.lang || 'en').slice(0,5);
    const honeypot = String(body.honeypot || '');
    let message = normalize(String(body.message || ''));

    if (honeypot) return json({ error: 'blocked' }, 403);
    if (!policy.allowedProviders.includes(provider)) return json({ error:'bad provider' }, 400);
    if (!message) return json({ error:'empty' }, 400);
    if (message.length > policy.maxChars) message = message.slice(0, policy.maxChars);

    // Scan
    for (const pat of policy.bannedPatterns) {
      const re = new RegExp(pat, 'g');
      if (re.test(message)) return json({ error: 'rejected' }, 400);
    }

    // Replay window (clientless): enforce minimal interval per IP via durable-free KV-less token
    const key = `ts:${ip}`;
    const lastTs = await caches.default.match(new Request(`https://cache/${key}`));
    if (lastTs) {
      const delta = now - Number((await lastTs.text()).trim());
      if (delta < policy.minIntervalMs) return json({ error: 'slow down' }, 429);
    }
    await caches.default.put(new Request(`https://cache/${key}`), new Response(String(now), { headers:{ 'Cache-Control':'max-age=5' }}));

    // Package for Bridge
    const ts = String(now);
    const kid = 'kid-' + now.toString(36);
    const payload = { provider, lang, message, ts, kid };

    const sig = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}`);
    const out = await fetch(env.BRIDGE_URL.replace(/\/+$/,'') + '/v1/relay', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-KID': kid,
        'X-TS': ts,
        'X-SIG': sig
      },
      body: JSON.stringify(payload)
    });

    const resp = await safeJson(out);
    // Normalize Bridge reply
    if (!out.ok) return json({ error: resp.error || 'bridge_error' }, out.status);

    return json({
      text: typeof resp.text === 'string' ? resp.text : JSON.stringify(resp),
      provider: resp.provider || provider,
      model: resp.model || null,
      kid
    }, 200, strictHeaders());
  }
};

/* helpers */
function normalize(s){ return s.normalize('NFKC').replace(/\u0000/g,'').replace(/[ \t]+/g,' ').trim(); }
async function hmac(secret, msg){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function loadPolicy(env){ return JSON.parse(await (await fetch(new URL('./policy.json', import.meta.url))).text()); }
async function safeJson(res){ try{ return await res.json(); }catch{ return {}; } }
function json(obj, status=200, extraHeaders={}){
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type':'application/json', ...extraHeaders }});
}
function strictHeaders(){
  return {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff'
  };
}
