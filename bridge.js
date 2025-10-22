export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/v1/relay') {
      return j({ error: 'not_found' }, 404);
    }

    // --- Required headers from Gateway
    const ts  = request.headers.get('X-TS')  || '';
    const kid = request.headers.get('X-KID') || '';
    const sig = request.headers.get('X-SIG') || '';
    const origin = request.headers.get('X-ORIGIN') || '';

    let body;
    try { body = await request.json(); } catch { return j({ error:'invalid_json' }, 400); }

    const now = Date.now();
    if (!ts || Math.abs(now - Number(ts)) > 120000) return j({ error:'stale' }, 401);

    const provider = String(body.provider || '').toLowerCase();
    const lang = (body.lang || 'en').slice(0,5);
    const message = norm(String(body.message || ''));

    // --- Recompute HMAC (anti-tamper)
    const expect = await hmac(env.GATEWAY_PSK, `${ts}.${kid}.${message}`);
    if (!tse(sig, expect)) return j({ error:'bad_sig' }, 401);

    // --- Re-run policy scan
    const policy = await loadPolicy();
    if (!policy.allowedProviders.includes(provider)) return j({ error:'bad_provider' }, 400);
    if (!message) return j({ error:'empty' }, 400);
    if (message.length > policy.maxChars) return j({ error:'too_long' }, 400);
    if (violates(message, policy.bannedPatterns)) return j({ error:'rejected' }, 400);

    // --- Provider routing
    if (provider === 'studio') {
      const model = env.GEMINI_MODEL || 'gemini-1.5-flash-latest';
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(env.GEMINI_API_KEY)}`;
      const req = {
        contents: [{ role: 'user', parts: [{ text: message }]}],
        safetySettings: [],
        generationConfig: { temperature: 0.6 }
      };
      const r = await withTimeout(fetch(endpoint, {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify(req)
      }), 30000);
      const data = await safeJson(r);
      if (!r.ok) return j({ error: data.error?.message || 'studio_error' }, r.status);
      const text = extractGeminiText(data) || '';
      return j({ provider:'studio', model, text }, 200, strict());
    }

    if (provider === 'codex') {
      const model = env.OPENAI_MODEL || 'gpt-4o-mini';
      const r = await withTimeout(fetch('https://api.openai.com/v1/chat/completions', {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'Authorization': `Bearer ${env.OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          model,
          messages: [{ role:'user', content: message }],
          temperature: 0.6
        })
      }), 30000);
      const data = await safeJson(r);
      if (!r.ok) return j({ error: data.error?.message || 'openai_error' }, r.status);
      const text = data.choices?.[0]?.message?.content || '';
      return j({ provider:'codex', model, text }, 200, strict());
    }

    return j({ error:'unhandled' }, 400);
  }
};

/* ---------- helpers ---------- */
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
function violates(s, pats){ return pats.some(p => new RegExp(p,'g').test(s)); }
async function hmac(secret, msg){
  const key = await crypto.subtle.importKey('raw', enc(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(msg));
  return hex(new Uint8Array(sig));
}
function tse(a,b){
  if (a.length !== b.length) return false;
  let r = 0; for (let i=0;i<a.length;i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function enc(s){ return new TextEncoder().encode(s); }
function hex(a){ return [...a].map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function safeJson(res){ try{ return await res.json(); } catch{ return {}; } }
function j(obj, status=200, extra={}){ return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type':'application/json', ...extra }}); }
function strict(){
  return {
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  };
}
async function withTimeout(promise, ms){
  const ctrl = new AbortController();
  const id = setTimeout(()=>ctrl.abort('timeout'), ms);
  try { return await promise.then(r=>r, e=>Promise.reject(e)); }
  finally { clearTimeout(id); }
}
/* Gemini extractor */
function extractGeminiText(d){
  try { return d.candidates?.[0]?.content?.parts?.map(p=>p.text).filter(Boolean).join('\n').trim() || ''; }
  catch { return ''; }
}

