export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/v1/relay') {
      return json({ error: 'Not found' }, 404);
    }

    // Verify HMAC
    const ts = request.headers.get('X-TS') || '';
    const kid = request.headers.get('X-KID') || '';
    const sig = request.headers.get('X-SIG') || '';
    const now = Date.now();
    if (!ts || Math.abs(now - Number(ts)) > 120000) return json({ error:'stale' }, 401);

    let body;
    try { body = await request.json(); } catch { return json({ error:'invalid json' }, 400); }
    const provider = String(body.provider || '').toLowerCase();
    const message = normalize(String(body.message || ''));
    const lang = (body.lang || 'en').slice(0,5);

    // Recompute signature
    const expect = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}`);
    if (!timingSafeEq(sig, expect)) return json({ error:'bad sig' }, 401);

    // Policy
    const policy = await loadPolicy(env);
    if (!policy.allowedProviders.includes(provider)) return json({ error:'bad provider' }, 400);
    if (!message) return json({ error:'empty' }, 400);
    if (message.length > policy.maxChars) return json({ error:'too long' }, 400);
    for (const pat of policy.bannedPatterns) {
      if (new RegExp(pat,'g').test(message)) return json({ error:'rejected' }, 400);
    }

    if (provider === 'studio') {
      const model = env.GEMINI_MODEL || 'gemini-1.5-flash-latest';
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(env.GEMINI_API_KEY)}`;
      // Google AI Studio (Gemini) — generateContent
      const req = {
        contents: [{ role: 'user', parts: [{ text: message }]}],
        safetySettings: [],
        generationConfig: { temperature: 0.6 }
      };
      const r = await fetch(endpoint, {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify(req)
      });
      const data = await safeJson(r);
      if (!r.ok) return json({ error: data.error?.message || 'studio_error' }, r.status);
      const text = extractGeminiText(data) || '';
      return json({ provider:'studio', model, text }, 200, strictHeaders());
    }

    if (provider === 'codex') {
      const urlCodex = env.CODEX_HTTP_URL;
      const r = await fetch(urlCodex, {
        method:'POST',
        headers:{ 'Content-Type':'application/json', 'X-KID': kid, 'X-TS': ts },
        body: JSON.stringify({ prompt: message, lang })
      });
      const data = await safeJson(r);
      if (!r.ok) return json({ error: data.error || 'codex_error' }, r.status);
      const text = typeof data.text === 'string' ? data.text : JSON.stringify(data);
      return json({ provider:'codex', model: data.model || null, text }, 200, strictHeaders());
    }

    return json({ error:'unhandled' }, 400);
  }
};

/* helpers */
function normalize(s){ return s.normalize('NFKC').replace(/\u0000/g,'').replace(/[ \t]+/g,' ').trim(); }
async function hmac(secret, msg){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function timingSafeEq(a,b){
  if (a.length !== b.length) return false;
  let r = 0; for (let i=0;i<a.length;i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
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
/* Gemini response normalizer */
function extractGeminiText(d){
  try{
    const c = d.candidates?.[0]?.content?.parts?.[0]?.text;
    return typeof c === 'string' ? c : '';
  }catch{ return ''; }
}
