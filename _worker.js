// Academia en ligne : serveur de synchronisation (Cloudflare Worker + base D1)
// Les accès sont contrôlés par VOTRE serveur d'activation (même appel /api/verify que l'application).
// Liaison D1 requise : nom "DB".  Variable facultative : LICENSE_VERIFY_URL.
const DEFAULT_LICENSE_URL = "https://licencemanager.ficheprobot.workers.dev/api/verify";
const COLLS = new Set(["students","payments","revenues","expenses","cashManual","teachers","salaryPayments","bulletins","journal","meta"]);
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "X-License-Key, X-Device, Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Max-Age": "86400"
};
const json = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { ...CORS, "Content-Type": "application/json" } });
async function sha256(t){
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
let schemaPret = false;   // les tables se créent toutes seules au premier appel : aucun SQL à coller
async function preparerBase(env) {
  if (schemaPret) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS schools (id TEXT PRIMARY KEY, created_at TEXT, seq INTEGER NOT NULL DEFAULT 0)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS items (school TEXT NOT NULL, coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT, seq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (school, coll, id))"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_items_seq ON items (school, seq)")
  ]);
  schemaPret = true;
}
const cache = new Map();   // résultat de vérification gardé quelques minutes (évite d'interroger le serveur de licences à chaque synchronisation)
async function verifierLicence(env, key, device) {
  const ck = key + "|" + device;
  const hit = cache.get(ck);
  if (hit && Date.now() - hit.t < (hit.ok ? 600000 : 30000)) return hit;
  try {
    const r = await fetch(env.LICENSE_VERIFY_URL || DEFAULT_LICENSE_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ license_key: key, device_fingerprint: device })
    });
    const j = await r.json();
    const res = { ok: !!j.valid, reason: j.reason || null, t: Date.now() };
    if (res.ok) {
      res.sid = (await sha256(key)).slice(0, 16);
      await env.DB.prepare("INSERT OR IGNORE INTO schools (id, created_at, seq) VALUES (?1, ?2, 0)").bind(res.sid, new Date().toISOString()).run();
    }
    cache.set(ck, res);
    return res;
  } catch (e) {
    if (hit && hit.ok) return hit;          // serveur de licences injoignable : on tolère une licence déjà validée
    return { ok: false, indisponible: true };
  }
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const texte = (t, st = 200) => new Response(t, { status: st, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    if (!env.DB) {
      return url.pathname === "/"
        ? texte("⚠️ Serveur actif, mais la base de données n'est pas liée.\nAllez dans Paramètres → Liaisons → Ajouter → Base de données D1, variable : DB.", 500)
        : json({ error: "base de données non liée (variable DB)" }, 500);
    }
    try {
      await preparerBase(env);
      if (req.method === "GET" && url.pathname === "/")
        return texte("✅ Academia en ligne : serveur actif, base de données prête.");

      const key = (req.headers.get("X-License-Key") || "").trim().toUpperCase();
      const device = (req.headers.get("X-Device") || "").trim();
      if (!key || !device) return json({ error: "licence requise" }, 401);
      const lic = await verifierLicence(env, key, device);
      if (lic.indisponible) return json({ error: "serveur de licences injoignable" }, 503);
      if (!lic.ok) return json({ error: "licence refusée", reason: lic.reason }, 401);
      const sid = lic.sid;

      // Lecture des changements depuis le numéro "since"
      if (url.pathname === "/api/sync" && req.method === "GET") {
        const since = Math.max(0, parseInt(url.searchParams.get("since") || "0", 10) || 0);
        const { results } = await env.DB.prepare("SELECT coll, id, data, seq, deleted FROM items WHERE school = ?1 AND seq > ?2 ORDER BY seq LIMIT 3000")
          .bind(sid, since).all();
        const last = results.length ? results[results.length - 1].seq : since;
        return json({ changes: results, seq: last, more: results.length === 3000 });
      }

      // Envoi de modifications
      if (url.pathname === "/api/push" && req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const ops = (body.ops || []).filter(o => o && COLLS.has(o.coll) && typeof o.id === "string" && o.id.length > 0 && o.id.length <= 80).slice(0, 200);
        if (!ops.length) return json({ ok: true });
        const r = await env.DB.prepare("UPDATE schools SET seq = seq + ?1 WHERE id = ?2 RETURNING seq").bind(ops.length, sid).first();
        let seq = r.seq - ops.length;
        const stmts = [];
        for (const o of ops) {
          seq++;
          let data = null, deleted = 1;
          if (o.op !== "del") {
            deleted = 0;
            let d = o.data;
            if (o.coll === "meta" && d && typeof d === "object") {
              // Compteurs de reçus : on ne revient jamais en arrière
              const old = await env.DB.prepare("SELECT data FROM items WHERE school = ?1 AND coll = 'meta' AND id = 'meta'").bind(sid).first();
              if (old && old.data) {
                const om = JSON.parse(old.data);
                for (const k of ["nextReceiptSeq", "nextSalaryReceiptSeq"]) if (typeof om[k] === "number") d[k] = Math.max(om[k], Number(d[k]) || 0);
              }
            }
            data = JSON.stringify(d === undefined ? null : d);
            if (data.length > 1500000) return json({ error: "élément trop volumineux" }, 413);
          }
          stmts.push(env.DB.prepare(
            "INSERT INTO items (school, coll, id, data, seq, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6) " +
            "ON CONFLICT (school, coll, id) DO UPDATE SET data = excluded.data, seq = excluded.seq, deleted = excluded.deleted"
          ).bind(sid, o.coll, o.id, data, seq, deleted));
        }
        await env.DB.batch(stmts);
        return json({ ok: true, seq });
      }
      return json({ error: "introuvable" }, 404);
    } catch (e) {
      if (req.method === "GET" && url.pathname === "/") return texte("⚠️ Serveur actif, mais la base ne répond pas : " + String(e && e.message).slice(0, 160), 500);
      return json({ error: "erreur serveur" }, 500);
    }
  }
};
