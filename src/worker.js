/**
 * Spazio Genesi ETS — Bot Telegram di attestazione (client puro di imgauth).
 *
 * Nessuna modifica a imgauth: questo Worker chiama solo la sua API pubblica
 * (POST /api/hash con bearer dedicato, /api/cert-pdf, /api/verify, /api/cert,
 * /api/ots, /api/status, /c/<hash>). Zero route Cloudflare custom: unico
 * endpoint proprio è POST /webhook (Telegram), su workers.dev di default.
 *
 * Canale "comodità dichiarato": a differenza del sito (dove il file non
 * lascia mai il dispositivo), qui il file transita per Telegram e per questo
 * Worker — l'impronta si calcola in streaming e i byte si scartano subito,
 * nulla viene salvato. Vedi P23-DESIGN-telegram-bot.md §1 per l'analisi
 * completa della decisione di privacy (non riaprirla senza il gestore).
 *
 * Endpoints:
 *   POST /webhook  → riceve gli update di Telegram (richiede header
 *                    X-Telegram-Bot-Api-Secret-Token corretto)
 *   GET  /ping     → health check
 *   (cron)         → pulizia giornaliera stato bot (retention 90gg)
 */

import { PDFDocument, PDFName, PDFRawStream } from "pdf-lib";
import pkg from "../package.json";

const APP_VERSION = pkg.version;

const TELEGRAM_API = "https://api.telegram.org";
const HEX64_RE = /^[0-9a-f]{64}$/i;
const VERIFY_WINDOW_MS = 10 * 60 * 1000; // 10 minuti: durata del modo /verifica e dell'"impronta attesa"

const GENERIC_ERROR_TEXT = "Il servizio ha un problema temporaneo — controlla /stato o riprova più tardi.";
const TOO_MANY_TEXT = "Troppe richieste in questo momento, riprova tra un minuto.";

// ── Testi (avvertenza onesta, aiuto, privacy) ────────────────────────────────
// Vedi P23-DESIGN §1 per il vincolo: la disclosure va mostrata PRIMA di
// scaricare qualunque file, e ogni esito di attestazione ripete la riga fissa.

const DISCLAIMER_TEXT =
  "⚠️ Canale comodità, non il canale a privacy totale.\n\n" +
  "Dal sito (attestazione.spaziogenesi.org) il file che attesti non lascia mai il tuo dispositivo: l'impronta si calcola nel browser.\n\n" +
  "Qui su Telegram, invece, il file che mi invii TRANSITA per i server di Telegram e per il nostro server: ne calcoliamo l'impronta e scartiamo subito i byte — non salviamo nulla — ma il transito avviene. Se per te conta la privacy assoluta, usa il sito.\n\n" +
  "Vuoi procedere comunque?";

const CHANNEL_NOTICE_TEXT =
  "Canale comodità: il file è transitato per Telegram e per il nostro server ed è già stato scartato. Per la privacy totale: attestazione.spaziogenesi.org";

const PHOTO_WARNING_TEXT =
  "Telegram ricomprime le foto: l'impronta non corrisponderebbe più al tuo file originale. " +
  "Inviamelo come file (documento): usa la graffetta 📎 → File, non la fotocamera/galleria diretta.";

const HELP_TEXT =
  "Comandi:\n" +
  "/attesta — attesta un file (modo predefinito)\n" +
  "/verifica — verifica un'impronta, un certificato o un file\n" +
  "/certificato <impronta> — recupera un certificato smarrito\n" +
  "/stato — stato dei servizi\n" +
  "/privacy — cosa salviamo e perché\n" +
  "/annulla — torna al modo predefinito\n" +
  "/aiuto — questo elenco";

function startText(env) {
  return (
    "Ciao! Sono il bot di attestazione di Spazio Genesi ETS.\n\n" +
    "Due canali, due livelli di privacy:\n" +
    "📍 Sito (" + env.CERT_SITE_BASE_URL + "): il file non lascia mai il tuo dispositivo.\n" +
    "📍 Qui in chat: canale di comodità — il file che mi invii transita per Telegram e per il nostro server (che lo scarta subito, nulla viene salvato).\n\n" +
    HELP_TEXT
  );
}

function privacyText(env) {
  return (
    "Cosa salvo: il tuo id Telegram, se hai accettato l'avvertenza sopra, e contatori d'uso giornalieri (cancellati dopo 90 giorni).\n\n" +
    "Il file che mi invii NON viene mai salvato: ne calcolo l'impronta in streaming e scarto subito i byte.\n\n" +
    "Telegram è un fornitore di trasporto autonomo (non un nostro responsabile del trattamento).\n\n" +
    "Dettagli completi: " + env.CERT_SITE_BASE_URL + "/privacy.html"
  );
}

// ── Helpers generici ──────────────────────────────────────────────────────

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Confronto a tempo costante (stesso pattern di imgauth › timingSafeEqualHex):
// evita che un timing attack riveli il secret del webhook un carattere alla volta.
function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Giorno civile a Roma (bucket delle quote giornaliere), stesso approccio di
// imgauth › dayRome: Intl.DateTimeFormat gestisce l'ora legale automaticamente.
function dayRome(ms = Date.now()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Rome", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(new Date(ms));
}

// ── API Telegram (fetch diretto, nessuna dipendenza framework) ──────────────

async function tgCall(env, method, payload) {
  const res = await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => null);
  if (!data || !data.ok) throw new Error(`Telegram ${method} fallita: ${data && data.description}`);
  return data.result;
}

// Invio best-effort: un errore di rete verso Telegram non deve far esplodere
// il webhook (che ha già risposto 200 prima di arrivare qui, vedi fetch()).
async function sendMessage(env, chatId, text, opts = {}) {
  try {
    await tgCall(env, "sendMessage", { chat_id: chatId, text, disable_web_page_preview: true, ...opts });
  } catch { /* best-effort */ }
}

async function answerCallbackQuery(env, id, text, showAlert = false) {
  try {
    await tgCall(env, "answerCallbackQuery", { callback_query_id: id, text, show_alert: showAlert });
  } catch { /* best-effort */ }
}

async function tgSendDocument(env, chatId, filename, bytes, mime, caption) {
  const form = new FormData();
  form.append("chat_id", String(chatId));
  if (caption) form.append("caption", caption);
  form.append("document", new Blob([bytes], { type: mime }), filename);
  try {
    const res = await fetch(`${TELEGRAM_API}/bot${env.TELEGRAM_BOT_TOKEN}/sendDocument`, { method: "POST", body: form });
    if (!res.ok) await sendMessage(env, chatId, GENERIC_ERROR_TEXT);
  } catch {
    await sendMessage(env, chatId, GENERIC_ERROR_TEXT);
  }
}

async function tgGetFilePath(env, fileId) {
  const result = await tgCall(env, "getFile", { file_id: fileId });
  return result.file_path;
}

function tgFileDownloadUrl(env, filePath) {
  return `${TELEGRAM_API}/file/bot${env.TELEGRAM_BOT_TOKEN}/${filePath}`;
}

// Scarica un file di Telegram e ne calcola l'impronta SHA-256 IN STREAMING
// (crypto.DigestStream, API nativa del runtime Workers): i byte non vengono
// mai bufferizzati in memoria né salvati — coerente con l'invariante di
// privacy del canale (P23-DESIGN §1.3).
async function downloadAndHash(env, doc) {
  const maxBytes = Number(env.MAX_TG_FILE_BYTES || 20971520);
  if (doc.file_size && doc.file_size > maxBytes) throw new Error("too_large");
  const filePath = await tgGetFilePath(env, doc.file_id);
  const res = await fetch(tgFileDownloadUrl(env, filePath));
  if (!res.ok || !res.body) throw new Error("download_failed");
  const digestStream = new crypto.DigestStream("SHA-256");
  await res.body.pipeTo(digestStream);
  const digest = await digestStream.digest;
  return bufToHex(digest);
}

// Scarica i byte completi di un file (usato SOLO per i certificati PDF, che
// vanno interamente in memoria per essere analizzati con pdf-lib — non è
// "l'opera" dell'utente, è un documento pubblico legato a un'impronta già
// nota; il tetto dimensione resta comunque MAX_TG_FILE_BYTES).
async function downloadBytes(env, fileId) {
  const filePath = await tgGetFilePath(env, fileId);
  const res = await fetch(tgFileDownloadUrl(env, filePath));
  if (!res.ok) throw new Error("download_failed");
  return new Uint8Array(await res.arrayBuffer());
}

// ── Stato D1 (bot_users / bot_usage, schema/bot.sql) ─────────────────────────

async function getOrCreateUser(env, tgUserId) {
  const row = await env.DB.prepare(
    `SELECT tg_user_id, accepted_at, mode, mode_expires, verify_expect, pending_cert, last_seen
     FROM bot_users WHERE tg_user_id = ?`
  ).bind(tgUserId).first();
  if (row) return row;
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO bot_users (tg_user_id, last_seen) VALUES (?, ?) ON CONFLICT(tg_user_id) DO NOTHING`
  ).bind(tgUserId, now).run();
  return { tg_user_id: tgUserId, accepted_at: null, mode: null, mode_expires: null, verify_expect: null, pending_cert: null, last_seen: now };
}

async function touchUser(env, tgUserId) {
  await getOrCreateUser(env, tgUserId);
  await env.DB.prepare(`UPDATE bot_users SET last_seen = ? WHERE tg_user_id = ?`).bind(Date.now(), tgUserId).run();
}

async function setAccepted(env, tgUserId) {
  await getOrCreateUser(env, tgUserId);
  await env.DB.prepare(`UPDATE bot_users SET accepted_at = ? WHERE tg_user_id = ?`).bind(Date.now(), tgUserId).run();
}

async function setMode(env, tgUserId, mode, expiresAt) {
  await getOrCreateUser(env, tgUserId);
  await env.DB.prepare(`UPDATE bot_users SET mode = ?, mode_expires = ? WHERE tg_user_id = ?`).bind(mode, expiresAt, tgUserId).run();
}

// verify_expect e mode_expires condividono la stessa scadenza: entrambi
// rappresentano la stessa "finestra di verifica" (vedi P23-DESIGN §4.4).
async function setVerifyExpect(env, tgUserId, hash, expiresAt) {
  await getOrCreateUser(env, tgUserId);
  await env.DB.prepare(`UPDATE bot_users SET verify_expect = ?, mode_expires = ? WHERE tg_user_id = ?`).bind(hash, expiresAt, tgUserId).run();
}

async function setPendingCert(env, tgUserId, obj) {
  await getOrCreateUser(env, tgUserId);
  await env.DB.prepare(`UPDATE bot_users SET pending_cert = ? WHERE tg_user_id = ?`).bind(obj ? JSON.stringify(obj) : null, tgUserId).run();
}

// true = richiesta consentita (e già conteggiata). Race a bassa criticità
// accettata: non è un limite adversarial-critical, solo un tetto di buon senso
// (stesso spirito "best-effort" del rate limiting per-IP di imgauth).
async function bumpQuota(env, tgUserId, kind, limit) {
  const day = dayRome();
  const col = kind === "attest" ? "attests" : "verifies";
  const row = await env.DB.prepare(
    `SELECT ${col} AS n FROM bot_usage WHERE tg_user_id = ? AND day = ?`
  ).bind(tgUserId, day).first();
  const used = row ? row.n : 0;
  if (used >= limit) return { ok: false, used, limit };
  await env.DB.prepare(
    `INSERT INTO bot_usage (tg_user_id, day, ${col}) VALUES (?, ?, 1)
     ON CONFLICT(tg_user_id, day) DO UPDATE SET ${col} = ${col} + 1`
  ).bind(tgUserId, day).run();
  return { ok: true, used: used + 1, limit };
}

async function verifyQuotaOk(env, chatId, tgUserId) {
  const q = await bumpQuota(env, tgUserId, "verify", Number(env.BOT_DAILY_VERIFY_LIMIT || 20));
  if (!q.ok) await sendMessage(env, chatId, `Hai raggiunto il limite di ${q.limit} verifiche al giorno da bot. Riprova domani.`);
  return q.ok;
}

// Gate di accettazione (P23-DESIGN §1.2 + §4.3.1): niente download senza
// consenso esplicito, una volta per utente.
async function ensureAccepted(env, chatId, tgUserId) {
  const user = await getOrCreateUser(env, tgUserId);
  if (user.accepted_at) return true;
  await sendMessage(env, chatId, DISCLAIMER_TEXT, {
    reply_markup: { inline_keyboard: [[
      { text: "✅ Ho capito, procedi", callback_data: "accept_disclaimer" },
      { text: "❌ Preferisco il sito", callback_data: "decline_disclaimer" },
    ]] },
  });
  return false;
}

// ── API imgauth (client puro: solo fetch verso endpoint già esistenti) ──────

async function apiHash(env, payload) {
  const res = await fetch(`${env.IMGAUTH_BASE_URL}/api/hash`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${env.IMGAUTH_API_KEY}` },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, json };
}

async function apiCertPdf(env, payload) {
  const res = await fetch(`${env.IMGAUTH_BASE_URL}/api/cert-pdf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) return { ok: false, status: res.status };
  return { ok: true, status: 200, bytes: new Uint8Array(await res.arrayBuffer()) };
}

async function apiVerify(env, fields) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) if (v) form.append(k, v);
  const res = await fetch(`${env.IMGAUTH_BASE_URL}/api/verify`, { method: "POST", body: form });
  return res.json().catch(() => ({}));
}

// GET /c/<hash>: usato SOLO come check di presenza in archivio (status code),
// mai per leggere la pagina — il body viene scartato subito.
async function checkArchive(env, hash) {
  try {
    const res = await fetch(`${env.IMGAUTH_BASE_URL}/c/${hash}`);
    if (res.body) { try { await res.body.cancel(); } catch { /* ignora */ } }
    return res.status === 200;
  } catch {
    return false;
  }
}

// ── Estrazione dati dal certificato PDF ──────────────────────────────────────
// Il sito (authweb) fa questo lato client con pdf.js (getTextContent, testato
// in produzione). pdf.js richiede un DOM e non gira in un Cloudflare Worker:
// qui si usa pdf-lib (già usato da imgauth per SCRIVERE i certificati, quindi
// provato in questo stesso runtime) solo per estrarre i frammenti di testo
// grezzi dai content stream. Le REGOLE di riconoscimento sotto sono le STESSE,
// verbatim, di imgauthweb/index.html › extractCertFields: non sono state
// re-inventate, solo applicate a una sorgente di frammenti diversa.
// ⚠️ Da validare con un certificato reale in FASE 2 (vedi P23-DESIGN §6).

// Estrae le stringhe letterali "(...)" da un content stream PDF decodificato
// (operandi di Tj/TJ). Non è un parser PDF completo: gestisce solo l'escaping
// più comune (\(, \), \\, \n, \r, \t) — sufficiente per testo WinAnsi semplice
// come quello disegnato da imgauth (niente ottali: cleanMeta già filtra i
// caratteri non stampabili prima della firma).
function extractLiteralStrings(bytes) {
  const CHUNK = 8192;
  let text = "";
  for (let i = 0; i < bytes.length; i += CHUNK) text += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));

  const out = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] !== "(") { i++; continue; }
    let depth = 1, j = i + 1, buf = "";
    while (j < text.length && depth > 0) {
      const c = text[j];
      if (c === "\\") {
        const n = text[j + 1];
        if (n === "n") buf += "\n";
        else if (n === "r") buf += "\r";
        else if (n === "t") buf += "\t";
        else if (n === "(" || n === ")" || n === "\\") buf += n;
        else buf += n ?? "";
        j += 2;
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") { depth--; if (depth === 0) { j++; break; } }
      buf += c;
      j++;
    }
    out.push(buf);
    i = j;
  }
  return out;
}

async function inflateZlib(bytes) {
  const ds = new DecompressionStream("deflate");
  const writer = ds.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

// Tutti i frammenti di testo letterale di TUTTI gli stream del PDF (pagina +
// XObject dei campi AcroForm appiattiti da form.flatten() in fillCertificatePdf):
// un approccio "a strascico" — decodifica ogni stream FlateDecode e ne estrae
// le stringhe — più semplice e robusto, per il nostro solo template, che
// seguire i riferimenti Resources/XObject uno per uno.
async function extractPdfFragments(bytes) {
  const pdfDoc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false });
  const fragments = [];
  for (const [, obj] of pdfDoc.context.enumerateIndirectObjects()) {
    if (!(obj instanceof PDFRawStream)) continue;
    const filter = obj.dict.get(PDFName.of("Filter"));
    const filterName = filter && typeof filter.asString === "function" ? filter.asString() : null;
    const raw = typeof obj.getContents === "function" ? obj.getContents() : obj.contents;
    if (!raw || raw.length > 2 * 1024 * 1024) continue; // difesa CPU: stream anomali fuori scope
    let decoded;
    if (filterName === "FlateDecode") {
      try { decoded = await inflateZlib(raw); } catch { continue; }
    } else if (!filterName) {
      decoded = raw;
    } else {
      continue; // filtri non testuali (es. DCTDecode delle immagini): non servono
    }
    fragments.push(...extractLiteralStrings(decoded));
  }
  return fragments;
}

// Stesse regex di imgauthweb/index.html › extractCertFields (righe ~1946-1977),
// applicate a `fragments` (equivalente al `lines` di authweb) invece che ai
// TextItem di pdf.js. `tight` = tutto il testo concatenato SENZA spazi, come
// in authweb: robusto rispetto a come i frammenti vengono spezzati.
function parseCertFragments(fragments) {
  const tight = fragments.join("").replace(/\s+/g, "");
  const out = { hash: "", attestazione: "", hmac: "", titolo: "", autore: "", anno: "", note: "" };

  const att = tight.match(/SHA-256:([0-9a-f]{64})@(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/i);
  if (att) { out.hash = att[1].toLowerCase(); out.attestazione = "SHA-256:" + out.hash + "@" + att[2]; }

  let hm = tight.match(/FirmaHMAC\(server\):([A-Za-z0-9+/]{43}=)/);
  if (!hm) hm = tight.match(/([A-Za-z0-9+/]{43}=)/); // fallback: unica stringa base64 con padding
  if (hm) out.hmac = hm[1];

  // Dati dichiarati: blocco tra l'intestazione e l'avvertenza (stesso
  // algoritmo di authweb, su `fragments` invece che su `lines`).
  const start = fragments.findIndex((l) => /Dati dichiarati dall.?autore/i.test(l));
  const end = fragments.findIndex((l) => /Dati forniti dall.?autore al momento/i.test(l));
  if (start >= 0 && end > start) {
    const acc = { titolo: [], autore: [], anno: [], note: [] };
    const labels = [
      ["titolo", /^Titolo:\s*(.*)$/], ["autore", /^Autore:\s*(.*)$/],
      ["anno", /^Anno\/versione:\s*(.*)$/], ["note", /^Note:\s*(.*)$/],
    ];
    let cur = null;
    for (const raw of fragments.slice(start + 1, end)) {
      const l = raw.trim();
      if (!l) continue;
      let matched = false;
      for (const [k, re] of labels) {
        const m = l.match(re);
        if (m) { cur = k; acc[k].push(m[1]); matched = true; break; }
      }
      if (!matched && cur) acc[cur].push(l);
    }
    for (const k of ["titolo", "autore", "anno", "note"]) {
      const v = acc[k].join(" ").replace(/\s+/g, " ").trim();
      if (v) out[k] = v;
    }
  }
  return out;
}

async function extractCertFromPdfBytes(bytes) {
  const fragments = await extractPdfFragments(bytes);
  const parsed = parseCertFragments(fragments);
  if (!parsed.hash) return null;
  return parsed;
}

// ── Flussi: attestazione ──────────────────────────────────────────────────

async function handleAttestDocument(env, message) {
  const chatId = message.chat.id, userId = message.from.id, doc = message.document;
  if (!(await ensureAccepted(env, chatId, userId))) return;

  const quota = await bumpQuota(env, userId, "attest", Number(env.BOT_DAILY_ATTEST_LIMIT || 5));
  if (!quota.ok) {
    await sendMessage(env, chatId, `Hai raggiunto il limite di ${quota.limit} attestazioni al giorno da bot. Riprova domani, oppure usa il sito: ${env.CERT_SITE_BASE_URL}`);
    return;
  }

  let sha256;
  try {
    sha256 = await downloadAndHash(env, doc);
  } catch (e) {
    await sendMessage(env, chatId, e.message === "too_large"
      ? `Questo file supera i 20 MB: da Telegram non posso riceverlo. Usa il sito (fino a 1 GB, e il file non lascia il tuo dispositivo): ${env.CERT_SITE_BASE_URL}`
      : "Non sono riuscito a scaricare il file da Telegram. Riprova.");
    return;
  }

  const r = await apiHash(env, {
    sha256, name: doc.file_name || "opera", type: doc.mime_type || "application/octet-stream",
    size: doc.file_size, titolo: message.caption ? message.caption.slice(0, 150) : undefined,
  });
  if (r.status === 429) { await sendMessage(env, chatId, TOO_MANY_TEXT); return; }
  if (!r.ok) { await sendMessage(env, chatId, GENERIC_ERROR_TEXT); return; }

  await setPendingCert(env, userId, r.json);
  const certUrl = `${env.CERT_SITE_BASE_URL}/c/${r.json.sha256}`;
  const text = `✅ Attestata.\nImpronta: ${r.json.sha256}\nData: ${r.json.timestamp_leggibile}\n\n${CHANNEL_NOTICE_TEXT}`;
  await sendMessage(env, chatId, text, {
    reply_markup: { inline_keyboard: [[
      { text: "📄 Scarica il certificato PDF", callback_data: "dl_cert" },
      { text: "🔗 Link permanente", url: certUrl },
    ]] },
  });
}

async function handleCallbackDlCert(env, cb) {
  const chatId = cb.message.chat.id, userId = cb.from.id;
  await answerCallbackQuery(env, cb.id);
  const user = await getOrCreateUser(env, userId);
  if (!user.pending_cert) {
    await sendMessage(env, chatId, "Non ho un'attestazione recente da trasformare in PDF: rimandami il file.");
    return;
  }
  const payload = JSON.parse(user.pending_cert);
  const r = await apiCertPdf(env, payload);
  if (r.status === 429) { await sendMessage(env, chatId, TOO_MANY_TEXT); return; }
  if (!r.ok) { await sendMessage(env, chatId, GENERIC_ERROR_TEXT); return; }
  await tgSendDocument(env, chatId, `certificato_${payload.sha256.slice(0, 12)}.pdf`, r.bytes, "application/pdf", "Il tuo certificato firmato.");
}

// ── Flussi: verifica ─────────────────────────────────────────────────────

async function handleHashLookup(env, chatId, userId, hash) {
  if (!(await verifyQuotaOk(env, chatId, userId))) return;
  await setVerifyExpect(env, userId, hash, Date.now() + VERIFY_WINDOW_MS);

  const inArchive = await checkArchive(env, hash);
  if (!inArchive) {
    await sendMessage(env, chatId, "⚪ Nessuna attestazione in archivio per questa impronta.");
    return;
  }
  const certUrl = `${env.CERT_SITE_BASE_URL}/c/${hash}`;
  await sendMessage(env, chatId, "🟢 Opera attestata.\nSe mi invii ora il file (entro 10 minuti), verifico che corrisponda.", {
    reply_markup: { inline_keyboard: [
      [{ text: "🔗 Pagina pubblica", url: certUrl }],
      [{ text: "📄 Recupera il PDF", url: `${env.IMGAUTH_BASE_URL}/api/cert?hash=${hash}` }],
      [{ text: "⚓ Prova blockchain", url: `${env.IMGAUTH_BASE_URL}/api/ots?hash=${hash}` }],
    ] },
  });
}

async function handleVerifyCompareFile(env, message, expectedHash) {
  const chatId = message.chat.id, userId = message.from.id, doc = message.document;
  if (!(await ensureAccepted(env, chatId, userId))) return;
  if (!(await verifyQuotaOk(env, chatId, userId))) return;
  await setVerifyExpect(env, userId, null, null);

  let sha256;
  try {
    sha256 = await downloadAndHash(env, doc);
  } catch (e) {
    await sendMessage(env, chatId, e.message === "too_large"
      ? `Questo file supera i 20 MB. Usa il sito: ${env.CERT_SITE_BASE_URL}`
      : "Non sono riuscito a scaricare il file da Telegram. Riprova.");
    return;
  }
  await sendMessage(env, chatId, sha256 === expectedHash
    ? "🟢 Il file corrisponde all'impronta indicata."
    : `🔴 Il file NON corrisponde all'impronta indicata.\nImpronta attesa: ${expectedHash}\nImpronta calcolata: ${sha256}`);
}

async function handleVerifyArchiveCheckFile(env, message) {
  const chatId = message.chat.id, userId = message.from.id, doc = message.document;
  if (!(await ensureAccepted(env, chatId, userId))) return;
  if (!(await verifyQuotaOk(env, chatId, userId))) return;

  let sha256;
  try {
    sha256 = await downloadAndHash(env, doc);
  } catch (e) {
    await sendMessage(env, chatId, e.message === "too_large"
      ? `Questo file supera i 20 MB. Usa il sito: ${env.CERT_SITE_BASE_URL}`
      : "Non sono riuscito a scaricare il file da Telegram. Riprova.");
    return;
  }
  const inArchive = await checkArchive(env, sha256);
  const certUrl = `${env.CERT_SITE_BASE_URL}/c/${sha256}`;
  await sendMessage(env, chatId, inArchive
    ? `🟢 Opera attestata.\nImpronta: ${sha256}\n🔗 ${certUrl}`
    : `⚪ Nessuna attestazione in archivio per questo file.\nImpronta: ${sha256}`);
}

async function handleCertificatePdf(env, message, bytes) {
  const chatId = message.chat.id, userId = message.from.id;
  let extracted;
  try {
    extracted = await extractCertFromPdfBytes(bytes);
  } catch {
    extracted = null;
  }
  if (!extracted) {
    await sendMessage(env, chatId, "Non sembra un nostro certificato: non trovo un'impronta valida in questo PDF.");
    return;
  }

  await setVerifyExpect(env, userId, extracted.hash, Date.now() + VERIFY_WINDOW_MS);
  const certUrl = `${env.CERT_SITE_BASE_URL}/c/${extracted.hash}`;

  if (!extracted.hmac) {
    const inArchive = await checkArchive(env, extracted.hash);
    await sendMessage(env, chatId, inArchive
      ? `⚪ Non riesco a leggere la firma da questo PDF, ma l'impronta risulta in archivio.\nPer la verifica completa (autenticità + integrità), trascina il PDF sul sito: ${certUrl}`
      : "⚪ Non riesco a leggere la firma da questo PDF e l'impronta non risulta in archivio.");
    return;
  }

  const result = await apiVerify(env, {
    hash: extracted.hash, attestazione: extracted.attestazione, hmac: extracted.hmac,
    titolo: extracted.titolo, autore: extracted.autore, anno: extracted.anno, note: extracted.note,
  });

  if (result.hmac_valido === true) {
    await sendMessage(env, chatId, `🟢 Certificato autentico.\nImpronta: ${extracted.hash}\n🔗 ${certUrl}\n\nSe mi invii ora il file (entro 10 minuti), verifico anche che corrisponda.`);
    return;
  }
  if (extracted.titolo || extracted.autore || extracted.anno || extracted.note) {
    // I metadati dichiarati concorrono alla firma: un'estrazione imperfetta
    // (es. un titolo andato a capo su più righe) può produrre un falso
    // negativo. Fallback onesto: solo check d'archivio, mai un "alterato"
    // ingiustificato (vedi P23-DESIGN §4.4).
    const inArchive = await checkArchive(env, extracted.hash);
    await sendMessage(env, chatId,
      "⚪ Non riesco a confermare la firma con certezza (il certificato include dati dichiarati che potrei non aver letto perfettamente).\n" +
      (inArchive ? "L'impronta risulta comunque in archivio.\n" : "L'impronta non risulta in archivio.\n") +
      `Per la verifica completa, trascina il PDF sul sito: ${env.CERT_SITE_BASE_URL}`);
    return;
  }
  await sendMessage(env, chatId, "🔴 La firma NON è valida: il certificato risulta alterato o non è nostro.");
}

async function handleIncomingPdf(env, message) {
  const chatId = message.chat.id, userId = message.from.id, doc = message.document;
  const maxBytes = Number(env.MAX_TG_FILE_BYTES || 20971520);
  if (doc.file_size && doc.file_size > maxBytes) {
    await sendMessage(env, chatId, "Questo PDF supera i 20 MB: non riesco a leggerlo da qui.");
    return;
  }
  if (!(await verifyQuotaOk(env, chatId, userId))) return;

  let bytes;
  try {
    bytes = await downloadBytes(env, doc.file_id);
  } catch {
    await sendMessage(env, chatId, "Non sono riuscito a scaricare il PDF da Telegram. Riprova.");
    return;
  }
  await handleCertificatePdf(env, message, bytes);
}

// ── Comandi ──────────────────────────────────────────────────────────────

async function cmdAttesta(env, chatId, userId) {
  await setMode(env, userId, "attest", null);
  await sendMessage(env, chatId, "Modo attestazione. Inviami il file come documento (non come foto); la didascalia, se presente, diventa il titolo dichiarato.");
}

async function cmdVerifica(env, chatId, userId) {
  await setMode(env, userId, "verify", Date.now() + VERIFY_WINDOW_MS);
  await sendMessage(env, chatId, "Modo verifica (attivo 10 minuti). Inviami l'impronta SHA-256, il certificato PDF, oppure il file dell'opera.");
}

async function cmdAnnulla(env, chatId, userId) {
  await setMode(env, userId, "attest", null);
  await setVerifyExpect(env, userId, null, null);
  await sendMessage(env, chatId, "Tornato al modo predefinito (attestazione).");
}

async function cmdCertificato(env, chatId, arg) {
  const hash = String(arg || "").trim().toLowerCase();
  if (!HEX64_RE.test(hash)) {
    await sendMessage(env, chatId, "Uso: /certificato <impronta SHA-256 a 64 caratteri esadecimali>");
    return;
  }
  const res = await fetch(`${env.IMGAUTH_BASE_URL}/api/cert?hash=${hash}`);
  if (res.status === 404) { await sendMessage(env, chatId, "Nessun certificato in archivio per questa impronta."); return; }
  if (!res.ok) { await sendMessage(env, chatId, GENERIC_ERROR_TEXT); return; }
  const bytes = new Uint8Array(await res.arrayBuffer());
  await tgSendDocument(env, chatId, `certificato-${hash.slice(0, 12)}.pdf`, bytes, "application/pdf");
}

async function cmdStato(env, chatId) {
  const res = await fetch(`${env.IMGAUTH_BASE_URL}/api/status`);
  if (!res.ok) { await sendMessage(env, chatId, "Non riesco a leggere lo stato dei servizi in questo momento."); return; }
  const s = await res.json();
  const dot = (v) => (v === "ok" ? "🟢" : v === "degraded" ? "🟡" : v === "down" ? "🔴" : "⚪");
  const text = [
    "Stato dei servizi:",
    `${dot(s.worker)} Motore di attestazione`,
    `${dot(s.archive)} Archivio certificati`,
    `${dot(s.signer)} Firma crittografica`,
    `${dot(s.anchor)} Ancoraggio blockchain`,
    "",
    `Dettagli: ${env.CERT_SITE_BASE_URL}/status/`,
  ].join("\n");
  await sendMessage(env, chatId, text);
}

async function handleCommand(env, message) {
  const chatId = message.chat.id, userId = message.from.id;
  const [rawCmd, ...rest] = message.text.trim().split(/\s+/);
  const cmd = rawCmd.replace(/@.*$/, "").toLowerCase();
  const arg = rest.join(" ").trim();

  switch (cmd) {
    case "/start": return sendMessage(env, chatId, startText(env));
    case "/aiuto": case "/help": return sendMessage(env, chatId, HELP_TEXT);
    case "/attesta": return cmdAttesta(env, chatId, userId);
    case "/verifica": return cmdVerifica(env, chatId, userId);
    case "/annulla": return cmdAnnulla(env, chatId, userId);
    case "/certificato": return cmdCertificato(env, chatId, arg);
    case "/stato": return cmdStato(env, chatId);
    case "/privacy": return sendMessage(env, chatId, privacyText(env));
    default: return sendMessage(env, chatId, `Comando non riconosciuto.\n\n${HELP_TEXT}`);
  }
}

// ── Instradamento update ─────────────────────────────────────────────────

async function handleDocumentMessage(env, message) {
  const userId = message.from.id, doc = message.document;
  if (doc.mime_type === "application/pdf") return handleIncomingPdf(env, message);

  const user = await getOrCreateUser(env, userId);
  const now = Date.now();
  const expectActive = user.verify_expect && user.mode_expires && user.mode_expires > now;
  if (expectActive) return handleVerifyCompareFile(env, message, user.verify_expect);

  const currentMode = user.mode === "verify" && user.mode_expires && user.mode_expires > now ? "verify" : "attest";
  if (currentMode === "verify") return handleVerifyArchiveCheckFile(env, message);
  return handleAttestDocument(env, message);
}

async function handleCallback(env, cb) {
  if (!cb.message || cb.message.chat.type !== "private") { await answerCallbackQuery(env, cb.id); return; }
  if (cb.data === "accept_disclaimer") {
    await answerCallbackQuery(env, cb.id, "Fatto");
    await setAccepted(env, cb.from.id);
    await sendMessage(env, cb.message.chat.id, "Perfetto — ora rinviami il file da attestare.");
    return;
  }
  if (cb.data === "decline_disclaimer") {
    await answerCallbackQuery(env, cb.id);
    await sendMessage(env, cb.message.chat.id, `Va benissimo — trovi la privacy totale sul sito: ${env.CERT_SITE_BASE_URL}`);
    return;
  }
  if (cb.data === "dl_cert") return handleCallbackDlCert(env, cb);
  await answerCallbackQuery(env, cb.id);
}

async function handleUpdate(env, update) {
  if (update.callback_query) return handleCallback(env, update.callback_query);

  const message = update.message;
  if (!message || !message.chat || message.chat.type !== "private" || !message.from) return;
  await touchUser(env, message.from.id);

  if (message.photo) { await sendMessage(env, message.chat.id, PHOTO_WARNING_TEXT); return; }
  if (message.text && message.text.startsWith("/")) return handleCommand(env, message);
  if (message.document) return handleDocumentMessage(env, message);
  if (message.text) {
    const trimmed = message.text.trim();
    if (HEX64_RE.test(trimmed)) return handleHashLookup(env, message.chat.id, message.from.id, trimmed.toLowerCase());
  }
  await sendMessage(env, message.chat.id, HELP_TEXT);
}

// ── Cron: pulizia giornaliera (retention, P23-DESIGN §4.6) ──────────────────

async function handleScheduled(env) {
  const cutoffDay = dayRome(Date.now() - 90 * 86400000);
  await env.DB.prepare(`DELETE FROM bot_usage WHERE day < ?`).bind(cutoffDay).run();
  await env.DB.prepare(
    `UPDATE bot_users SET pending_cert = NULL, verify_expect = NULL
     WHERE last_seen < ? AND (pending_cert IS NOT NULL OR verify_expect IS NOT NULL)`
  ).bind(Date.now() - 86400000).run();
}

// ── Entry point ──────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/ping") {
      return jsonResponse({ ok: true, version: APP_VERSION });
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      const secretHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
      if (!env.TELEGRAM_WEBHOOK_SECRET || !timingSafeEqualStr(secretHeader, env.TELEGRAM_WEBHOOK_SECRET)) {
        return new Response("Forbidden", { status: 403 });
      }
      let update;
      try { update = await request.json(); } catch { return new Response("Bad Request", { status: 400 }); }
      // Risponde 200 subito: il lavoro vero avviene in background, evitando i
      // retry-storm di Telegram su elaborazioni lente o fallite a metà.
      ctx.waitUntil(handleUpdate(env, update).catch(() => {}));
      return new Response("OK", { status: 200 });
    }

    return new Response("Not found", { status: 404 });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },
};
